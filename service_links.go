package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"synapse/internal/authelia"
	"synapse/internal/db"
	"synapse/internal/kuma"
	"synapse/internal/logging"
	"synapse/internal/npm"
	synclib "synapse/internal/sync"
)

// apiError carries an HTTP status alongside an error message so integration
// helpers can distinguish user errors (400) from upstream failures (502).
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

// apiStatus extracts the HTTP status from an error. Defaults to 502 for
// unannotated integration errors.
func apiStatus(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.status
	}
	return http.StatusBadGateway
}

// --- Service links ---

// ServiceLinkView is a service link enriched with resolved instance names for
// display in the UI.
type ServiceLinkView struct {
	ID               int64      `json:"id"`
	ServiceName      string     `json:"service_name"`
	NPMInstanceID    int        `json:"npm_instance_id"`
	NPMInstanceName  string     `json:"npm_instance_name,omitempty"`
	NPMHostName      string     `json:"npm_host_name,omitempty"`
	NPMDetails       string     `json:"npm_details,omitempty"`
	KumaInstanceID   int        `json:"kuma_instance_id"`
	KumaInstanceName string     `json:"kuma_instance_name,omitempty"`
	KumaMonitorID    int        `json:"kuma_monitor_id"`
	KumaMonitorName  string     `json:"kuma_monitor_name,omitempty"`
	KumaDetails      string     `json:"kuma_details,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
}

// serviceLinkInput is the mutable payload for creating/updating a link. Target
// instance fields are pointers so partial updates can distinguish "unchanged"
// from "cleared" (0).
type serviceLinkInput struct {
	ServiceName     string `json:"service_name"`
	NPMInstanceID   *int   `json:"npm_instance_id"`
	NPMHostName     string `json:"npm_host_name"`
	KumaInstanceID  *int   `json:"kuma_instance_id"`
	KumaMonitorID   *int   `json:"kuma_monitor_id"`
	KumaMonitorName string `json:"kuma_monitor_name"`

	// AutheliaInstanceID, when set, ensures an Authelia access_control rule
	// exists for the service's derived domains as part of the link save.
	AutheliaInstanceID *int   `json:"authelia_instance_id"`
	AutheliaPolicy     string `json:"authelia_policy"`
	DryRun             *bool  `json:"dry_run"`

	// EnsureMissing, when true, auto-creates missing NPM hosts / Kuma monitors
	// (derived from the compose service) instead of failing the link.
	EnsureMissing bool `json:"ensure_missing"`
}

func (app *App) instanceNameMaps() (npmNames, kumaNames map[int]string) {
	npmNames = make(map[int]string)
	kumaNames = make(map[int]string)
	if insts, err := app.database.GetNPMInstances(); err == nil {
		for _, inst := range insts {
			npmNames[int(inst.ID)] = inst.Name
		}
	}
	if insts, err := app.database.GetKumaInstances(); err == nil {
		for _, inst := range insts {
			kumaNames[int(inst.ID)] = inst.Name
		}
	}
	return npmNames, kumaNames
}

func toServiceLinkView(l db.ServiceLink, npmNames, kumaNames map[int]string) ServiceLinkView {
	return ServiceLinkView{
		ID:               l.ID,
		ServiceName:      l.ServiceName,
		NPMInstanceID:    l.NPMInstanceID,
		NPMInstanceName:  npmNames[l.NPMInstanceID],
		NPMHostName:      l.NPMHostName,
		NPMDetails:       l.NPMDetails,
		KumaInstanceID:   l.KumaInstanceID,
		KumaInstanceName: kumaNames[l.KumaInstanceID],
		KumaMonitorID:    l.KumaMonitorID,
		KumaMonitorName:  l.KumaMonitorName,
		KumaDetails:      l.KumaDetails,
		CreatedAt:        l.CreatedAt,
		UpdatedAt:        l.UpdatedAt,
	}
}

// loadComposeService returns the compose ServiceDef for a service name.
func (app *App) loadComposeService(name string) (synclib.ServiceDef, error) {
	s := app.settings()
	services, err := synclib.LoadServices(s.ComposePath)
	if err != nil {
		return synclib.ServiceDef{}, fmt.Errorf("failed to read compose file: %w", err)
	}
	svc, ok := services[name]
	if !ok {
		return synclib.ServiceDef{}, fmt.Errorf("service %q not found in compose file", name)
	}
	return svc, nil
}

// fetchNPMHostByName resolves a proxy host by one of its domain names and
// returns the cached-detail JSON snapshot on the link.
func (app *App) resolveNPMTarget(link *db.ServiceLink, instanceID int, hostName, serviceName string, ensureMissing bool) error {
	client, err := app.npmRegistry.Get(instanceID)
	if err != nil {
		return &apiError{http.StatusBadRequest, err.Error()}
	}
	if strings.TrimSpace(hostName) == "" && !ensureMissing {
		return &apiError{http.StatusBadRequest, "npm_host_name is required when linking to an NPM instance"}
	}
	hosts, err := client.GetProxyHostsFull(context.Background())
	if err != nil {
		return &apiError{http.StatusBadGateway, err.Error()}
	}
	for i := range hosts {
		for _, dn := range hosts[i].DomainNames {
			if dn == hostName {
				link.NPMInstanceID = instanceID
				link.NPMHostName = hosts[i].DomainNames[0]
				details, _ := json.Marshal(hosts[i])
				link.NPMDetails = string(details)
				return nil
			}
		}
	}

	// Target not found: auto-create from the compose service when requested.
	if ensureMissing && serviceName != "" {
		svc, err := app.loadComposeService(serviceName)
		if err != nil {
			return &apiError{http.StatusBadRequest, err.Error()}
		}
		cfg, ok := synclib.DeriveNPMHost(serviceName, svc)
		if !ok || len(cfg.DomainNames) == 0 {
			return &apiError{http.StatusBadRequest, fmt.Sprintf("could not derive a domain for service %q (add a synapse.domains label)", serviceName)}
		}
		created, err := client.CreateProxyHost(cfg)
		if err != nil {
			return &apiError{http.StatusBadGateway, fmt.Sprintf("failed to create NPM proxy host for %q: %v", serviceName, err)}
		}
		link.NPMInstanceID = instanceID
		if len(created.DomainNames) > 0 {
			link.NPMHostName = created.DomainNames[0]
		} else {
			link.NPMHostName = cfg.DomainNames[0]
		}
		details, _ := json.Marshal(created)
		link.NPMDetails = string(details)
		return nil
	}

	return &apiError{http.StatusBadRequest, fmt.Sprintf("NPM proxy host %q not found", hostName)}
}

// resolveKumaTarget resolves a Kuma monitor by id and/or name and caches its
// details on the link.
func (app *App) resolveKumaTarget(link *db.ServiceLink, instanceID, monitorID int, monitorName, serviceName string, ensureMissing bool) error {
	client, err := app.kumaRegistry.Get(instanceID)
	if err != nil {
		return &apiError{http.StatusBadRequest, err.Error()}
	}
	if monitorID <= 0 && strings.TrimSpace(monitorName) == "" && !ensureMissing {
		return &apiError{http.StatusBadRequest, "kuma_monitor_id or kuma_monitor_name is required when linking to a Kuma instance"}
	}
	monitors, err := client.QueryMonitorsViaSocketIO()
	if err != nil {
		return &apiError{http.StatusBadGateway, err.Error()}
	}
	for i := range monitors {
		m := &monitors[i]
		if monitorID > 0 && m.ID == monitorID {
			link.KumaInstanceID = instanceID
			link.KumaMonitorID = m.ID
			link.KumaMonitorName = m.Name
			details, _ := json.Marshal(m)
			link.KumaDetails = string(details)
			return nil
		}
		if monitorName != "" && m.Name == monitorName {
			link.KumaInstanceID = instanceID
			link.KumaMonitorID = m.ID
			link.KumaMonitorName = m.Name
			details, _ := json.Marshal(m)
			link.KumaDetails = string(details)
			return nil
		}
	}

	// Target not found: auto-create from the compose service when requested.
	if ensureMissing && serviceName != "" {
		svc, err := app.loadComposeService(serviceName)
		if err != nil {
			return &apiError{http.StatusBadRequest, err.Error()}
		}
		monitorType, url, container, _ := synclib.DeriveKumaMonitor(serviceName, svc)
		if monitorType != "http" && monitorType != "docker" {
			return &apiError{http.StatusBadRequest, fmt.Sprintf("could not derive a monitor for service %q", serviceName)}
		}

		// Prefer an existing monitor with the derived display name.
		for i := range monitors {
			if monitors[i].Name == serviceName {
				link.KumaInstanceID = instanceID
				link.KumaMonitorID = monitors[i].ID
				link.KumaMonitorName = monitors[i].Name
				details, _ := json.Marshal(&monitors[i])
				link.KumaDetails = string(details)
				return nil
			}
		}

		id, err := client.AddMonitorViaSocketIO(monitorType, serviceName, url, container, 0)
		if err != nil {
			return &apiError{http.StatusBadGateway, fmt.Sprintf("failed to create Kuma monitor for %q: %v", serviceName, err)}
		}
		if tagIDs := parseKumaDefaultTags(app.settings().KumaDefaultTags); len(tagIDs) > 0 && id > 0 {
			for _, tagID := range tagIDs {
				if err := client.AddMonitorTagViaSocketIO(id, tagID); err != nil {
					logging.LogWarn("app", "Failed to add default tag to monitor",
						slog.Int("monitor_id", id),
						slog.Int("tag_id", tagID),
						slog.String("error", err.Error()),
					)
				}
			}
		}
		created := kuma.KumaMonitor{
			ID:              id,
			Name:            serviceName,
			Type:            monitorType,
			URL:             url,
			DockerContainer: container,
			Interval:        60,
			RetryInterval:   0,
			MaxRetries:      0,
		}
		link.KumaInstanceID = instanceID
		link.KumaMonitorID = id
		link.KumaMonitorName = serviceName
		details, _ := json.Marshal(&created)
		link.KumaDetails = string(details)
		return nil
	}

	return &apiError{http.StatusBadRequest, "Kuma monitor not found on the target instance"}
}

// ensureAutheliaRule ensures an Authelia access_control rule exists for the
// service's derived domains. Returns the sync actions performed. The instance
// must exist and be enabled (caller maps errors to a 400 response). The
// effective policy is the per-link policy when set, otherwise the instance's
// default policy; domain-keyed instance overrides still win.
func (app *App) ensureAutheliaRule(serviceName string, instanceID int, policy string, dryRun bool) ([]authelia.SyncAction, error) {
	inst, err := app.database.GetAutheliaInstance(int64(instanceID))
	if err != nil || inst == nil || !inst.Enabled {
		return nil, fmt.Errorf("authelia instance not found or disabled")
	}
	svc, err := app.loadComposeService(serviceName)
	if err != nil {
		return nil, err
	}
	domains := synclib.ServiceDomains(serviceName, svc)
	if len(domains) == 0 {
		return nil, fmt.Errorf("could not derive domains for service %q", serviceName)
	}
	entries := make([]npm.ProxyEntry, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, npm.ProxyEntry{CNAME: d, Container: serviceName})
	}
	var overrides map[string]string
	if inst.Overrides != "" && inst.Overrides != "{}" {
		json.Unmarshal([]byte(inst.Overrides), &overrides)
	}
	effectiveDefault := inst.DefaultPolicy
	if policy != "" {
		effectiveDefault = policy
	}
	return authelia.EnsureDomainRules(inst.ConfigPath, inst.DBPath, entries, effectiveDefault, overrides, dryRun)
}

// ServiceLinks lists all persisted service links with resolved instance names.
func (app *App) ServiceLinks(c *gin.Context) {
	links, err := app.database.GetServiceLinks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	npmNames, kumaNames := app.instanceNameMaps()
	result := make([]ServiceLinkView, 0, len(links))
	for _, l := range links {
		result = append(result, toServiceLinkView(l, npmNames, kumaNames))
	}
	c.JSON(http.StatusOK, result)
}

// CreateServiceLink persists a link between a compose service and an NPM proxy
// host and/or Kuma monitor, validating the service against the compose file
// and caching live integration details.
func (app *App) CreateServiceLink(c *gin.Context) {
	var input serviceLinkInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(input.ServiceName) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "service_name is required"})
		return
	}
	if _, err := app.loadComposeService(input.ServiceName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	link := db.ServiceLink{
		ServiceName: input.ServiceName,
		CreatedAt:   time.Now(),
	}
	if input.NPMInstanceID != nil && *input.NPMInstanceID > 0 {
		if err := app.resolveNPMTarget(&link, *input.NPMInstanceID, input.NPMHostName, input.ServiceName, input.EnsureMissing); err != nil {
			c.JSON(apiStatus(err), gin.H{"error": err.Error()})
			return
		}
	}
	if input.KumaInstanceID != nil && *input.KumaInstanceID > 0 {
		if err := app.resolveKumaTarget(&link, *input.KumaInstanceID, deref(input.KumaMonitorID), input.KumaMonitorName, input.ServiceName, input.EnsureMissing); err != nil {
			c.JSON(apiStatus(err), gin.H{"error": err.Error()})
			return
		}
	}

	var autheliaActions []authelia.SyncAction
	if input.AutheliaInstanceID != nil && *input.AutheliaInstanceID > 0 {
		actions, err := app.ensureAutheliaRule(input.ServiceName, *input.AutheliaInstanceID, input.AutheliaPolicy, derefBool(input.DryRun))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		autheliaActions = actions
	}

	created, err := app.database.UpsertServiceLink(&link)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	npmNames, kumaNames := app.instanceNameMaps()
	c.JSON(http.StatusOK, gin.H{
		"link":             toServiceLinkView(*created, npmNames, kumaNames),
		"authelia_actions": autheliaActions,
	})
}

// UpdateServiceLink changes the targets of an existing link, refreshing cached
// details for changed targets. Passing instance_id = 0 clears that side.
func (app *App) UpdateServiceLink(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid link id"})
		return
	}
	var input serviceLinkInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	link, err := app.database.GetServiceLink(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service link not found"})
		return
	}

	if input.NPMInstanceID != nil {
		if *input.NPMInstanceID <= 0 {
			link.NPMInstanceID = 0
			link.NPMHostName = ""
			link.NPMDetails = ""
		} else if err := app.resolveNPMTarget(link, *input.NPMInstanceID, input.NPMHostName, input.ServiceName, input.EnsureMissing); err != nil {
			c.JSON(apiStatus(err), gin.H{"error": err.Error()})
			return
		}
	}
	if input.KumaInstanceID != nil {
		if *input.KumaInstanceID <= 0 {
			link.KumaInstanceID = 0
			link.KumaMonitorID = 0
			link.KumaMonitorName = ""
			link.KumaDetails = ""
		} else if err := app.resolveKumaTarget(link, *input.KumaInstanceID, deref(input.KumaMonitorID), input.KumaMonitorName, input.ServiceName, input.EnsureMissing); err != nil {
			c.JSON(apiStatus(err), gin.H{"error": err.Error()})
			return
		}
	}

	var autheliaActions []authelia.SyncAction
	if input.AutheliaInstanceID != nil && *input.AutheliaInstanceID > 0 {
		actions, err := app.ensureAutheliaRule(input.ServiceName, *input.AutheliaInstanceID, input.AutheliaPolicy, derefBool(input.DryRun))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		autheliaActions = actions
	}

	if err := app.database.UpdateServiceLink(link); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	updated, err := app.database.GetServiceLink(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	npmNames, kumaNames := app.instanceNameMaps()
	c.JSON(http.StatusOK, gin.H{
		"link":             toServiceLinkView(*updated, npmNames, kumaNames),
		"authelia_actions": autheliaActions,
	})
}

// DeleteServiceLink removes a service link.
func (app *App) DeleteServiceLink(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid link id"})
		return
	}
	if err := app.database.DeleteServiceLink(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// RefreshServiceLink re-pulls the cached NPM/Kuma details from the live
// integrations and updates the link's updated_at timestamp.
func (app *App) RefreshServiceLink(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid link id"})
		return
	}
	link, err := app.database.GetServiceLink(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service link not found"})
		return
	}
	if link.NPMInstanceID > 0 {
		if err := app.resolveNPMTarget(link, link.NPMInstanceID, link.NPMHostName, link.ServiceName, false); err != nil {
			c.JSON(apiStatus(err), gin.H{"error": err.Error()})
			return
		}
	}
	if link.KumaInstanceID > 0 {
		if err := app.resolveKumaTarget(link, link.KumaInstanceID, link.KumaMonitorID, link.KumaMonitorName, link.ServiceName, false); err != nil {
			c.JSON(apiStatus(err), gin.H{"error": err.Error()})
			return
		}
	}
	if err := app.database.UpdateServiceLink(link); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	updated, err := app.database.GetServiceLink(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	npmNames, kumaNames := app.instanceNameMaps()
	c.JSON(http.StatusOK, toServiceLinkView(*updated, npmNames, kumaNames))
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

// --- NPM proxy host management ---

// NPMProxyHostView flattens an NPM proxy host with its source instance.
type NPMProxyHostView struct {
	InstanceID   int    `json:"instance_id"`
	InstanceName string `json:"instance_name,omitempty"`
	npm.ProxyHost
}

// npmProxyHostInput is the create/update payload for NPM proxy hosts.
type npmProxyHostInput struct {
	InstanceID            int                 `json:"instance_id"`
	DomainNames           []string            `json:"domain_names"`
	ForwardHost           string              `json:"forward_host"`
	ForwardPort           int                 `json:"forward_port"`
	ForwardScheme         string              `json:"forward_scheme"`
	Enabled               *bool               `json:"enabled"`
	SSLForced             bool                `json:"ssl_forced"`
	CertificateID         int                 `json:"certificate_id"`
	HTTP2Support          bool                `json:"http2_support"`
	HSTSEnabled           bool                `json:"hsts_enabled"`
	HSTSSubdomains        bool                `json:"hsts_subdomains"`
	BlockExploits         bool                `json:"block_exploits"`
	CachingEnabled        bool                `json:"caching_enabled"`
	AllowWebsocketUpgrade bool                `json:"allow_websocket_upgrade"`
	AccessListID          int                 `json:"access_list_id"`
	AdvancedConfig        string              `json:"advanced_config"`
	Locations             []npm.ProxyLocation `json:"locations"`
	Meta                  map[string]any      `json:"meta"`
	ServiceName           string              `json:"service_name"`
}

func (in *npmProxyHostInput) toProxyHostCreate() npm.ProxyHostCreate {
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	return npm.ProxyHostCreate{
		DomainNames:           in.DomainNames,
		ForwardScheme:         in.ForwardScheme,
		ForwardHost:           in.ForwardHost,
		ForwardPort:           in.ForwardPort,
		Enabled:               enabled,
		SSLForced:             in.SSLForced,
		CertificateID:         in.CertificateID,
		HTTP2Support:          in.HTTP2Support,
		HSTSEnabled:           in.HSTSEnabled,
		HSTSSubdomains:        in.HSTSSubdomains,
		BlockExploits:         in.BlockExploits,
		CachingEnabled:        in.CachingEnabled,
		AllowWebsocketUpgrade: in.AllowWebsocketUpgrade,
		AccessListID:          in.AccessListID,
		AdvancedConfig:        in.AdvancedConfig,
		Locations:             in.Locations,
		Meta:                  in.Meta,
	}
}

// NPMProxyHosts lists full proxy-host configurations, aggregated across all
// enabled instances or filtered to one via ?instance=.
func (app *App) NPMProxyHosts(c *gin.Context) {
	instanceID := 0
	if v := c.Query("instance"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid instance query param"})
			return
		}
		instanceID = n
	}

	instances, _ := app.database.GetNPMInstances()
	nameMap := make(map[int]string)
	for _, inst := range instances {
		nameMap[int(inst.ID)] = inst.Name
	}

	result := []NPMProxyHostView{}
	if instanceID > 0 {
		client, err := app.npmRegistry.Get(instanceID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		hosts, err := client.GetProxyHostsFull(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		for _, h := range hosts {
			result = append(result, NPMProxyHostView{InstanceID: instanceID, InstanceName: nameMap[instanceID], ProxyHost: h})
		}
	} else {
		clients, _ := app.npmRegistry.All()
		for _, ic := range clients {
			hosts, err := ic.Client.GetProxyHostsFull(c.Request.Context())
			if err != nil {
				logging.LogWarn("app", "Failed to fetch proxy hosts from NPM instance",
					slog.Int("instance_id", ic.InstanceID),
					slog.String("error", err.Error()),
				)
				continue
			}
			for _, h := range hosts {
				result = append(result, NPMProxyHostView{InstanceID: ic.InstanceID, InstanceName: nameMap[ic.InstanceID], ProxyHost: h})
			}
		}
	}
	c.JSON(http.StatusOK, result)
}

// CreateNPMProxyHost creates a proxy host in an NPM instance. When
// service_name is supplied, missing fields are derived from the compose
// service's metadata (labels, container_name, published ports).
func (app *App) CreateNPMProxyHost(c *gin.Context) {
	var input npmProxyHostInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.InstanceID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "instance_id is required"})
		return
	}
	if err := app.checkNPMInstance(input.InstanceID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := input.toProxyHostCreate()
	if input.ServiceName != "" {
		svc, err := app.loadComposeService(input.ServiceName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if derived, ok := synclib.DeriveNPMHost(input.ServiceName, svc); ok {
			if len(cfg.DomainNames) == 0 {
				cfg.DomainNames = derived.DomainNames
			}
			if cfg.ForwardHost == "" {
				cfg.ForwardHost = derived.ForwardHost
			}
			if cfg.ForwardPort == 0 {
				cfg.ForwardPort = derived.ForwardPort
			}
			if cfg.ForwardScheme == "" {
				cfg.ForwardScheme = derived.ForwardScheme
			}
		}
	}

	if len(cfg.DomainNames) == 0 || cfg.ForwardHost == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain_names and forward_host are required (add a synapse.domains label or fill the form)"})
		return
	}

	client, err := app.npmRegistry.Get(input.InstanceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	host, err := client.CreateProxyHost(cfg)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	instances, _ := app.database.GetNPMInstances()
	nameMap := make(map[int]string)
	for _, inst := range instances {
		nameMap[int(inst.ID)] = inst.Name
	}
	c.JSON(http.StatusOK, NPMProxyHostView{InstanceID: input.InstanceID, InstanceName: nameMap[input.InstanceID], ProxyHost: host})
}

// UpdateNPMProxyHost updates an existing proxy host in an NPM instance.
func (app *App) UpdateNPMProxyHost(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy host id"})
		return
	}
	var input npmProxyHostInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.InstanceID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "instance_id is required"})
		return
	}
	if err := app.checkNPMInstance(input.InstanceID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := app.npmRegistry.Get(input.InstanceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	host, err := client.UpdateProxyHost(id, input.toProxyHostCreate())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	instances, _ := app.database.GetNPMInstances()
	nameMap := make(map[int]string)
	for _, inst := range instances {
		nameMap[int(inst.ID)] = inst.Name
	}
	c.JSON(http.StatusOK, NPMProxyHostView{InstanceID: input.InstanceID, InstanceName: nameMap[input.InstanceID], ProxyHost: host})
}

// checkNPMInstance verifies an NPM instance exists and is enabled.
func (app *App) checkNPMInstance(id int) error {
	inst, err := app.database.GetNPMInstance(int64(id))
	if err != nil || inst == nil {
		return fmt.Errorf("npm instance %d not found", id)
	}
	if !inst.Enabled {
		return fmt.Errorf("npm instance %d is disabled", id)
	}
	return nil
}

// --- Kuma monitor management ---

// kumaMonitorInput is the create/update payload for Kuma monitors.
type kumaMonitorInput struct {
	InstanceID      int    `json:"instance_id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	URL             string `json:"url"`
	DockerContainer string `json:"docker_container"`
	DockerHost      int    `json:"docker_host"`
	Interval        int    `json:"interval"`
	RetryInterval   int    `json:"retry_interval"`
	MaxRetries      int    `json:"maxretries"`
	ServiceName     string `json:"service_name"`
}

// checkKumaInstance verifies a Kuma instance exists, is enabled, and returns
// its display name.
func (app *App) checkKumaInstance(id int) (string, error) {
	inst, err := app.database.GetKumaInstance(int64(id))
	if err != nil || inst == nil {
		return "", fmt.Errorf("kuma instance %d not found", id)
	}
	if !inst.Enabled {
		return "", fmt.Errorf("kuma instance %d is disabled", id)
	}
	return inst.Name, nil
}

// CreateKumaMonitor creates a monitor in a Kuma instance via Socket.IO. When
// service_name is supplied and type/url/container are omitted, they are
// derived from the compose service (type inferred from its healthcheck).
func (app *App) CreateKumaMonitor(c *gin.Context) {
	var input kumaMonitorInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.InstanceID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "instance_id is required"})
		return
	}
	instName, err := app.checkKumaInstance(input.InstanceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	monitorType := strings.ToLower(input.Type)
	url := input.URL
	container := input.DockerContainer
	interval := input.Interval

	if input.ServiceName != "" {
		svc, err := app.loadComposeService(input.ServiceName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		dType, dURL, dContainer, dInterval := synclib.DeriveKumaMonitor(input.ServiceName, svc)
		if monitorType == "" {
			monitorType = dType
		}
		if url == "" && monitorType == "http" {
			url = dURL
		}
		if container == "" && monitorType == "docker" {
			container = dContainer
		}
		if interval == 0 {
			interval = dInterval
		}
	}

	if monitorType != "http" && monitorType != "docker" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be \"http\" or \"docker\""})
		return
	}
	if monitorType == "http" && url == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required for http monitors"})
		return
	}
	if monitorType == "docker" && container == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "docker_container is required for docker monitors"})
		return
	}

	client, err := app.kumaRegistry.Get(input.InstanceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// A docker monitor must reference a valid docker_host id (Kuma's
	// monitor.docker_host is a FK to docker_host(id); sending 0 trips a
	// SQLite "FOREIGN KEY constraint failed"). If the caller didn't provide
	// one, resolve it from the instance's docker host list.
	dockerHostID := input.DockerHost
	if monitorType == "docker" && dockerHostID <= 0 {
		dockerHostID = resolveDockerHost(client)
	}

	id, err := client.AddMonitorViaSocketIO(monitorType, input.Name, url, container, dockerHostID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	// Apply default tags (non-fatal).
	if tagIDs := parseKumaDefaultTags(app.settings().KumaDefaultTags); len(tagIDs) > 0 && id > 0 {
		for _, tagID := range tagIDs {
			if err := client.AddMonitorTagViaSocketIO(id, tagID); err != nil {
				logging.LogWarn("app", "Failed to add default tag to monitor",
					slog.Int("monitor_id", id),
					slog.Int("tag_id", tagID),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	c.JSON(http.StatusOK, KumaMonitorSummary{
		ID:              id,
		Name:            input.Name,
		Type:            monitorType,
		URL:             url,
		DockerContainer: container,
		InstanceID:      input.InstanceID,
		InstanceName:    instName,
	})
}

// resolveDockerHost returns a valid docker_host FK id for a docker monitor.
// Kuma's monitor.docker_host references docker_host(id) and rejects 0 with a
// SQLite "FOREIGN KEY constraint failed", so if no docker host can be found
// we return 0, which the caller maps to omitting the field entirely (Kuma
// treats a missing docker_host as NULL, which is FK-valid).
func resolveDockerHost(client *kuma.Client) int {
	hosts, err := client.QueryDockerHosts()
	if err != nil || len(hosts) == 0 {
		return 0
	}
	return hosts[0].ID
}

// UpdateKumaMonitor edits a monitor in a Kuma instance: rename, type change
// (docker↔http), or field updates. Renames propagate to referencing service
// links.
func (app *App) UpdateKumaMonitor(c *gin.Context) {
	kumaID, err := strconv.Atoi(c.Param("kumaId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor id"})
		return
	}
	instanceID, err := strconv.Atoi(c.Query("instance"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing instance query param"})
		return
	}
	instName, err := app.checkKumaInstance(instanceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var input kumaMonitorInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client, err := app.kumaRegistry.Get(instanceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	monitors, err := client.QueryMonitorsViaSocketIO()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	var cur *kuma.KumaMonitor
	for i := range monitors {
		if monitors[i].ID == kumaID {
			cur = &monitors[i]
			break
		}
	}
	if cur == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("monitor %d not found", kumaID)})
		return
	}

	// Build the full edit payload, overlaying the requested changes.
	payload := map[string]any{
		"name":          cur.Name,
		"type":          cur.Type,
		"interval":      cur.Interval,
		"retryInterval": cur.RetryInterval,
		"maxretries":    cur.MaxRetries,
	}
	if cur.Type == "http" {
		payload["url"] = cur.URL
	} else {
		payload["docker_container"] = cur.DockerContainer
		if cur.DockerHost > 0 {
			payload["docker_host"] = cur.DockerHost
		}
	}

	newType := cur.Type
	if input.Name != "" {
		payload["name"] = input.Name
	}
	if input.Type != "" {
		newType = input.Type
		switch newType {
		case "http":
			if input.URL == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "url is required when changing the monitor to http"})
				return
			}
			payload["type"] = "http"
			payload["url"] = input.URL
			delete(payload, "docker_container")
			delete(payload, "docker_host")
		case "docker":
			if input.DockerContainer == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "docker_container is required when changing the monitor to docker"})
				return
			}
			payload["type"] = "docker"
			payload["docker_container"] = input.DockerContainer
			if input.DockerHost > 0 {
				payload["docker_host"] = input.DockerHost
			} else if dh := resolveDockerHost(client); dh > 0 {
				payload["docker_host"] = dh
			}
			delete(payload, "url")
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "type must be \"http\" or \"docker\""})
			return
		}
	} else if cur.Type == "http" && input.URL != "" {
		payload["url"] = input.URL
	} else if cur.Type == "docker" && input.DockerContainer != "" {
		payload["docker_container"] = input.DockerContainer
		if input.DockerHost > 0 {
			payload["docker_host"] = input.DockerHost
		} else if dh := resolveDockerHost(client); dh > 0 {
			payload["docker_host"] = dh
		}
	}
	if input.Interval > 0 {
		payload["interval"] = input.Interval
	}
	if input.RetryInterval > 0 {
		payload["retryInterval"] = input.RetryInterval
	}
	if input.MaxRetries > 0 {
		payload["maxretries"] = input.MaxRetries
	}

	if err := client.EditMonitorViaSocketIO(kumaID, payload); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	// Propagate renames to referencing service links.
	if input.Name != "" && input.Name != cur.Name {
		app.updateLinksForKumaMonitor(instanceID, kumaID, input.Name, "")
	}

	// The edit invalidated the monitor cache; re-query for the canonical state
	// and refresh cached link details.
	updated := KumaMonitorSummary{
		ID:              kumaID,
		Name:            cur.Name,
		Type:            newType,
		URL:             cur.URL,
		DockerContainer: cur.DockerContainer,
		Interval:        cur.Interval,
		RetryInterval:   cur.RetryInterval,
		MaxRetries:      cur.MaxRetries,
		InstanceID:      instanceID,
		InstanceName:    instName,
	}
	if fresh, err := client.QueryMonitorsViaSocketIO(); err == nil {
		for i := range fresh {
			if fresh[i].ID == kumaID {
				updated = KumaMonitorSummary{
					ID:              fresh[i].ID,
					Name:            fresh[i].Name,
					Type:            fresh[i].Type,
					URL:             fresh[i].URL,
					DockerContainer: fresh[i].DockerContainer,
					Interval:        fresh[i].Interval,
					RetryInterval:   fresh[i].RetryInterval,
					MaxRetries:      fresh[i].MaxRetries,
					InstanceID:      instanceID,
					InstanceName:    instName,
				}
				details, _ := json.Marshal(fresh[i])
				app.updateLinksForKumaMonitor(instanceID, kumaID, fresh[i].Name, string(details))
				break
			}
		}
	}
	c.JSON(http.StatusOK, updated)
}

// DeleteKumaMonitor removes a monitor from a Kuma instance and clears any
// service links referencing it.
func (app *App) DeleteKumaMonitor(c *gin.Context) {
	kumaID, err := strconv.Atoi(c.Param("kumaId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor id"})
		return
	}
	instanceID, err := strconv.Atoi(c.Query("instance"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing instance query param"})
		return
	}
	if _, err := app.checkKumaInstance(instanceID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := app.kumaRegistry.Get(instanceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := client.DeleteMonitorViaSocketIO(kumaID); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	// Unlink any service links referencing this monitor.
	links, err := app.database.GetServiceLinks()
	if err == nil {
		for i := range links {
			l := &links[i]
			if l.KumaInstanceID == instanceID && l.KumaMonitorID == kumaID {
				l.KumaInstanceID = 0
				l.KumaMonitorID = 0
				l.KumaMonitorName = ""
				l.KumaDetails = ""
				if err := app.database.UpdateServiceLink(l); err != nil {
					logging.LogWarn("app", "Failed to unlink service link after monitor delete",
						slog.Int64("link_id", l.ID),
						slog.String("error", err.Error()),
					)
				}
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// parseKumaDefaultTags parses a Kuma default-tags setting value into tag IDs.
// Accepts JSON array ("[1,2]") or comma-separated ("1,2,3").
func parseKumaDefaultTags(raw string) []int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "[") {
		var arr []int
		if err := json.Unmarshal([]byte(raw), &arr); err == nil {
			return arr
		}
		// Try []string then parse.
		var sarr []string
		if err := json.Unmarshal([]byte(raw), &sarr); err == nil {
			var out []int
			for _, s := range sarr {
				if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
					out = append(out, n)
				}
			}
			return out
		}
		return nil
	}
	var out []int
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// updateLinksForKumaMonitor updates the Kuma monitor name/details on all
// service links referencing the given monitor.
func (app *App) updateLinksForKumaMonitor(instanceID, monitorID int, name, details string) {
	links, err := app.database.GetServiceLinks()
	if err != nil {
		return
	}
	for i := range links {
		l := &links[i]
		if l.KumaInstanceID == instanceID && l.KumaMonitorID == monitorID {
			if name != "" {
				l.KumaMonitorName = name
			}
			if details != "" {
				l.KumaDetails = details
			}
			if err := app.database.UpdateServiceLink(l); err != nil {
				logging.LogWarn("app", "Failed to update service link after monitor edit",
					slog.Int64("link_id", l.ID),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

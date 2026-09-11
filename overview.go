package main

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	synclib "synapse/internal/sync"
)

// overviewService is the public-safe service view for the board.
type overviewService struct {
	Name            string   `json:"name"`
	ContainerName   string   `json:"container_name"`
	Image           string   `json:"image"`
	Domains         []string `json:"domains"`
	PrimaryURL      string   `json:"primary_url"`
	MonitorURL      string   `json:"monitor_url"`
	MonitorType     string   `json:"monitor_type"`
	Group           string   `json:"group"`
	Icon            string   `json:"icon"`
	Description     string   `json:"description"`
	ContainerState  string   `json:"container_state,omitempty"`
	ContainerStatus string   `json:"container_status,omitempty"`
	InKuma          bool     `json:"in_kuma"`
	KumaStatus      *int     `json:"kuma_status,omitempty"`
	KumaUptime24h   *float64 `json:"kuma_uptime_24h,omitempty"`
	NPMHostName     string   `json:"npm_host_name,omitempty"`
	ForwardHost     string   `json:"forward_host,omitempty"`
	ForwardPort     int      `json:"forward_port,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

// overviewProxy is a public proxy host view.
type overviewProxy struct {
	CNAME         string `json:"cname"`
	Container     string `json:"container"`
	ForwardScheme string `json:"forward_scheme"`
	ForwardHost   string `json:"forward_host"`
	ForwardPort   int    `json:"forward_port"`
	Enabled       bool   `json:"enabled"`
	InstanceName  string `json:"instance_name"`
	InKuma        bool   `json:"in_kuma"`
}

// overviewMonitor is a public monitor view (no secrets).
type overviewMonitor struct {
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	URL          string   `json:"url,omitempty"`
	InstanceName string   `json:"instance_name"`
	Status       int      `json:"status"`
	Active       bool     `json:"active"`
	Tags         []string `json:"tags,omitempty"`
}

func labelGroup(labels map[string]string) string {
	for _, k := range []string{"synapse.group", "homepage.group", "homarr.group", "group"} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			return v
		}
	}
	// fallback to compose project or default
	return "General"
}

func labelIcon(labels map[string]string) string {
	for _, k := range []string{"synapse.icon", "homepage.icon", "homarr.icon", "icon"} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			return v
		}
	}
	return ""
}

func labelDesc(labels map[string]string) string {
	for _, k := range []string{"synapse.description", "homepage.description", "homarr.description", "description", "synapse.subtitle", "homepage.subtitle"} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			return v
		}
	}
	return ""
}

// PublicOverview returns aggregated, public-safe data for the Homer-like board.
// No authentication required.
func (app *App) PublicOverview(c *gin.Context) {
	s := app.settings()
	composePath := s.ComposePath
	servicesMap, err := synclib.LoadServices(composePath)
	if err != nil {
		servicesMap = map[string]synclib.ServiceDef{}
	}

	// Fetch Kuma monitors (for status + in_kuma)
	kumaClients, _ := app.kumaRegistry.All()
	kumaMonitors := []KumaMonitorSummary{}
	monitorByName := map[string]KumaMonitorSummary{}
	for _, ic := range kumaClients {
		monitors, err := ic.Client.QueryMonitorsViaSocketIO()
		if err != nil {
			continue
		}
		instName := ""
		if inst, _ := app.database.GetKumaInstance(int64(ic.InstanceID)); inst != nil {
			instName = inst.Name
		}
		for _, m := range monitors {
			summ := KumaMonitorSummary{
				ID: m.ID, Name: m.Name, Type: m.Type, URL: m.URL,
				DockerContainer: m.DockerContainer, Status: m.Status,
				Uptime24h: m.Uptime24h, Uptime7d: m.Uptime7d, Uptime1y: m.Uptime1y,
				AvgPing: m.Ping, LastMsg: m.LastMsg,
				Interval: m.Interval, RetryInterval: m.RetryInterval, MaxRetries: m.MaxRetries,
				Active: m.Active, InstanceID: ic.InstanceID, InstanceName: instName,
			}
			kumaMonitors = append(kumaMonitors, summ)
			if _, ok := monitorByName[m.Name]; !ok {
				monitorByName[m.Name] = summ
			}
			// also map container name variant
			if _, ok := monitorByName[m.DockerContainer]; !ok && m.DockerContainer != "" {
				monitorByName[m.DockerContainer] = summ
			}
		}
	}

	// Fetch NPM proxy hosts
	npmClients, _ := app.npmRegistry.All()
	npmByDomain := map[string]overviewProxy{}
	proxies := []overviewProxy{}
	for _, ic := range npmClients {
		hosts, err := ic.Client.GetProxyHostsFull(c.Request.Context())
		if err != nil {
			continue
		}
		instName := ""
		if inst, _ := app.database.GetNPMInstance(int64(ic.InstanceID)); inst != nil {
			instName = inst.Name
		}
		for _, h := range hosts {
			for _, dn := range h.DomainNames {
				p := overviewProxy{
					CNAME: dn, Container: h.ForwardHost,
					ForwardScheme: h.ForwardScheme, ForwardHost: h.ForwardHost, ForwardPort: h.ForwardPort,
					Enabled: h.Enabled, InstanceName: instName,
				}
				// mark in_kuma if any monitor matches this domain
				if _, ok := monitorByName[dn]; ok {
					p.InKuma = true
				}
				npmByDomain[dn] = p
				break
			}
			// also push full host as one entry (dedup by first domain)
			if len(h.DomainNames) > 0 {
				dn := h.DomainNames[0]
				proxies = append(proxies, overviewProxy{
					CNAME: dn, Container: h.ForwardHost,
					ForwardScheme: h.ForwardScheme, ForwardHost: h.ForwardHost, ForwardPort: h.ForwardPort,
					Enabled: h.Enabled, InstanceName: instName,
					InKuma: npmByDomain[dn].InKuma,
				})
			}
		}
	}

	// Build public services list enriched with Docker container state
	// collect container state map if docker available
	stateByName := map[string]struct{ state, status string }{}
	if app.dockerClient != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		containers, err := app.dockerClient.ListContainers(ctx)
		cancel()
		if err == nil {
			for _, ct := range containers {
				name := ""
				if len(ct.Names) > 0 {
					name = strings.TrimPrefix(ct.Names[0], "/")
				}
				if name != "" {
					stateByName[name] = struct{ state, status string }{ct.State, ct.Status}
				}
			}
		}
	}

	services := make([]overviewService, 0, len(servicesMap))
	for name, svc := range servicesMap {
		domains := synclib.ServiceDomains(name, svc)
		if domains == nil {
			domains = []string{}
		}
		primaryURL := ""
		if len(domains) > 0 {
			// prefer synapse.url label if set
			if u := strings.TrimSpace(svc.Labels["synapse.url"]); u != "" {
				primaryURL = u
			} else if u := strings.TrimSpace(svc.Labels["homepage.href"]); u != "" {
				primaryURL = u
			} else {
				primaryURL = "https://" + domains[0]
			}
		} else if svc.Ports != nil && len(svc.Ports) > 0 {
			// fallback to localhost port
		}
		monitorURL := synclib.ParseHealthcheck(name, svc)
		monitorType := "docker"
		if monitorURL != "" {
			monitorType = "http"
		}
		containerName := svc.ContainerName
		if containerName == "" {
			containerName = name
		}
		group := labelGroup(svc.Labels)
		icon := labelIcon(svc.Labels)
		desc := labelDesc(svc.Labels)

		// enrich with NPM & Kuma status
		inKuma := false
		var kumaStatus *int
		var kumaUptime *float64
		if m, ok := monitorByName[containerName]; ok {
			inKuma = true
			s := m.Status
			kumaStatus = &s
			if m.Uptime24h != 0 {
				v := m.Uptime24h
				kumaUptime = &v
			}
		} else if m, ok := monitorByName[name]; ok {
			inKuma = true
			s := m.Status
			kumaStatus = &s
		} else if len(domains) > 0 {
			if m, ok := monitorByName[domains[0]]; ok {
				inKuma = true
				s := m.Status
				kumaStatus = &s
			}
		}

		npmHost := ""
		fwdHost := ""
		fwdPort := 0
		if len(domains) > 0 {
			if p, ok := npmByDomain[domains[0]]; ok {
				npmHost = p.CNAME
				fwdHost = p.ForwardHost
				fwdPort = p.ForwardPort
			}
		}

		cs := ""
		cstat := ""
		if st, ok := stateByName[containerName]; ok {
			cs = st.state
			cstat = st.status
		} else if st, ok := stateByName[name]; ok {
			cs = st.state
			cstat = st.status
		}

		svcOut := overviewService{
			Name:            name,
			ContainerName:   containerName,
			Image:           svc.Image,
			Domains:         domains,
			PrimaryURL:      primaryURL,
			MonitorURL:      monitorURL,
			MonitorType:     monitorType,
			Group:           group,
			Icon:            icon,
			Description:     desc,
			ContainerState:  cs,
			ContainerStatus: cstat,
			InKuma:          inKuma,
			KumaStatus:      kumaStatus,
			KumaUptime24h:   kumaUptime,
			NPMHostName:     npmHost,
			ForwardHost:     fwdHost,
			ForwardPort:     fwdPort,
		}
		// collect tags from monitor if present
		if m, ok := monitorByName[containerName]; ok && len(m.Tags) > 0 {
			for _, t := range m.Tags {
				svcOut.Tags = append(svcOut.Tags, t.Name)
			}
		}
		services = append(services, svcOut)
	}

	sort.Slice(services, func(i, j int) bool {
		if services[i].Group != services[j].Group {
			return services[i].Group < services[j].Group
		}
		return services[i].Name < services[j].Name
	})

	// Build monitors public view
	outMonitors := make([]overviewMonitor, 0, len(kumaMonitors))
	for _, m := range kumaMonitors {
		tags := []string{}
		for _, t := range m.Tags {
			tags = append(tags, t.Name)
		}
		outMonitors = append(outMonitors, overviewMonitor{
			ID: m.ID, Name: m.Name, Type: m.Type, URL: m.URL,
			InstanceName: m.InstanceName, Status: m.Status, Active: m.Active, Tags: tags,
		})
	}

	// Build unique groups list
	groupSet := map[string]bool{}
	for _, s := range services {
		groupSet[s.Group] = true
	}
	groups := []string{}
	for g := range groupSet {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	c.Header("Cache-Control", "no-cache")
	c.JSON(http.StatusOK, gin.H{
		"version":   version,
		"generated": time.Now().Format(time.RFC3339),
		"services":  services,
		"proxies":   proxies,
		"monitors":  outMonitors,
		"groups":    groups,
		"stats": gin.H{
			"total_services": len(services),
			"total_proxies":  len(proxies),
			"total_monitors": len(outMonitors),
		},
	})
}

// OverviewPage serves the public Homer-like board.
func (app *App) OverviewPage(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
	c.HTML(http.StatusOK, "overview.html", gin.H{
		"Version": version,
	})
}

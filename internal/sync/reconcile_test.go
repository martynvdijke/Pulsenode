package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"synapse/internal/db"
	"synapse/internal/kuma"
	"synapse/internal/npm"
)

// writeReconcileCompose writes a compose file with synapse.* labels so the
// desired NPM host is derivable. The testdata compose file has no labels, so
// reconcile tests use their own.
func writeReconcileCompose(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/docker-compose.yml"
	content := `services:
  web:
    image: nginx
    container_name: nginx-web
    ports:
      - "8080:80"
    labels:
      synapse.domains: "app.example.com,www.app.example.com"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
  api:
    image: myapi
    container_name: myapi-api
    ports:
      - "9000:9000"
    labels:
      synapse.domain: "api.example.com"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write compose: %v", err)
	}
	return path
}

// mockNpmReconcile serves the full NPM REST surface: JWT auth, GET proxy
// hosts, POST create and PUT update. hosts is the GET response; records
// captured POST/PUT payloads and call counts.
func mockNpmReconcile(t *testing.T, instanceID int, hosts []npm.ProxyHost) (npm.InstanceClient, *npmReconcileRecorder) {
	t.Helper()
	rec := &npmReconcileRecorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":   "test-jwt-token",
			"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/nginx/proxy-hosts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rec.gets++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(hosts)
		case http.MethodPost:
			rec.posts++
			var cfg npm.ProxyHostCreate
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			rec.lastCreate = cfg
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(npm.ProxyHost{
				ID: 10, DomainNames: cfg.DomainNames,
				ForwardHost: cfg.ForwardHost, ForwardPort: cfg.ForwardPort,
				ForwardScheme: cfg.ForwardScheme, Enabled: cfg.Enabled,
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/nginx/proxy-hosts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rec.puts++
		var cfg npm.ProxyHostCreate
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		rec.lastUpdate = cfg
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(npm.ProxyHost{
			ID: 10, DomainNames: cfg.DomainNames,
			ForwardHost: cfg.ForwardHost, ForwardPort: cfg.ForwardPort,
			ForwardScheme: cfg.ForwardScheme, Enabled: cfg.Enabled,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return npm.InstanceClient{
		InstanceID: instanceID,
		Client:     npm.NewClient(srv.URL, "user", "pass"),
	}, rec
}

type npmReconcileRecorder struct {
	gets, posts, puts int
	lastCreate        npm.ProxyHostCreate
	lastUpdate        npm.ProxyHostCreate
}

// mockKumaReconcile sets hooks for Query, Add and Edit monitor calls.
func mockKumaReconcile(t *testing.T, instanceID int, existing []kuma.KumaMonitor) (kuma.InstanceClient, *kumaReconcileRecorder) {
	t.Helper()
	rec := &kumaReconcileRecorder{}
	c := kuma.NewClient("http://kuma-mock.invalid")
	c.SetTestHooks(&kuma.ClientTestHooks{
		QueryMonitors: func() ([]kuma.KumaMonitor, error) {
			return existing, nil
		},
		AddMonitor: func(monitorType, name, url, dockerContainer string, dockerHostID int) (int, error) {
			rec.adds++
			rec.lastAdd = kumaAddCall{MonitorType: monitorType, Name: name, URL: url, Container: dockerContainer}
			return 1, nil
		},
		EditMonitor: func(monitorID int, payload map[string]any) error {
			rec.edits++
			rec.lastEdit = kumaEditCall{MonitorID: monitorID, Payload: payload}
			return nil
		},
	})
	return kuma.InstanceClient{InstanceID: instanceID, Client: c}, rec
}

type kumaAddCall struct {
	MonitorType, Name, URL, Container string
}

type kumaEditCall struct {
	MonitorID int
	Payload   map[string]any
}

type kumaReconcileRecorder struct {
	adds, edits int
	lastAdd     kumaAddCall
	lastEdit    kumaEditCall
}

func TestRunReconcileCreatesMissing(t *testing.T) {
	d := setupTestDB(t)
	_, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1})
	if err != nil {
		t.Fatalf("create link: %v", err)
	}

	npmIC, npmRec := mockNpmReconcile(t, 1, nil)
	kumaIC, kumaRec := mockKumaReconcile(t, 1, nil)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: false}, func(p Progress) {})

	run := result.Run
	if run.Status != "completed" {
		t.Fatalf("expected completed, got %q (err=%q)", run.Status, run.ErrorMessage)
	}
	if run.Added != 2 {
		t.Errorf("expected 2 added (npm+kuma), got %d", run.Added)
	}
	if run.DryRun {
		t.Error("expected dry_run=false")
	}
	if npmRec.posts != 1 {
		t.Errorf("expected 1 NPM create, got %d", npmRec.posts)
	}
	if kumaRec.adds != 1 {
		t.Errorf("expected 1 Kuma add, got %d", kumaRec.adds)
	}
	// NPM create payload: domains, scheme, port from first published port,
	// host from container_name.
	if !strings.EqualFold(npmRec.lastCreate.ForwardScheme, "http") {
		t.Errorf("expected scheme http, got %q", npmRec.lastCreate.ForwardScheme)
	}
	if npmRec.lastCreate.ForwardHost != "nginx-web" {
		t.Errorf("expected forward_host nginx-web, got %q", npmRec.lastCreate.ForwardHost)
	}
	if npmRec.lastCreate.ForwardPort != 8080 {
		t.Errorf("expected forward_port 8080, got %d", npmRec.lastCreate.ForwardPort)
	}
	if len(npmRec.lastCreate.DomainNames) != 2 || npmRec.lastCreate.DomainNames[0] != "app.example.com" {
		t.Errorf("unexpected domains: %v", npmRec.lastCreate.DomainNames)
	}
	if !npmRec.lastCreate.Enabled {
		t.Error("expected desired host enabled")
	}
	// Kuma add: http monitor from healthcheck URL.
	if kumaRec.lastAdd.MonitorType != "http" {
		t.Errorf("expected http monitor, got %q", kumaRec.lastAdd.MonitorType)
	}
	if kumaRec.lastAdd.URL != "http://nginx-web:80/health" {
		t.Errorf("expected rewritten healthcheck URL, got %q", kumaRec.lastAdd.URL)
	}
	if kumaRec.lastAdd.Name != "nginx-web" {
		t.Errorf("expected display name nginx-web, got %q", kumaRec.lastAdd.Name)
	}
	// Changes recorded.
	if len(result.Changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(result.Changes))
	}
	if result.Changes[0].Action != "created" || result.Changes[1].Action != "created" {
		t.Errorf("expected both created, got %+v", result.Changes)
	}
	// Persisted run with source reconcile.
	runs, err := d.GetSyncRuns(5)
	if err != nil || len(runs) == 0 {
		t.Fatalf("expected persisted sync runs (err=%v)", err)
	}
	if runs[0].Source != "reconcile" || runs[0].DryRun {
		t.Errorf("unexpected persisted run: %+v", runs[0])
	}
}

func TestRunReconcileDryRun(t *testing.T) {
	d := setupTestDB(t)
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	npmIC, npmRec := mockNpmReconcile(t, 1, nil)
	kumaIC, kumaRec := mockKumaReconcile(t, 1, nil)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: true}, func(p Progress) {})

	if !result.Run.DryRun {
		t.Error("expected dry_run=true on run")
	}
	if result.Run.Added != 2 {
		t.Errorf("expected 2 intended additions, got %d", result.Run.Added)
	}
	if npmRec.posts != 0 {
		t.Errorf("dry run must not POST, got %d posts", npmRec.posts)
	}
	if kumaRec.adds != 0 {
		t.Errorf("dry run must not add monitors, got %d", kumaRec.adds)
	}
	// Dry-run reports intended changes.
	if len(result.Changes) != 2 {
		t.Errorf("expected 2 reported changes, got %d", len(result.Changes))
	}
	for _, c := range result.Changes {
		if c.Action != "created" {
			t.Errorf("expected created, got %q", c.Action)
		}
	}
}

func TestRunReconcileUpdatesDrift(t *testing.T) {
	d := setupTestDB(t)
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create link: %v", err)
	}

	// Live NPM host exists but drifted: wrong port and scheme http2.
	hosts := []npm.ProxyHost{{
		ID: 10, DomainNames: []string{"app.example.com", "www.app.example.com"},
		ForwardHost: "nginx-web", ForwardPort: 80, ForwardScheme: "http2", Enabled: true,
	}}
	npmIC, npmRec := mockNpmReconcile(t, 1, hosts)

	// Live Kuma monitor exists but interval drifted (60 vs desired 30).
	monitors := []kuma.KumaMonitor{{
		ID: 5, Name: "nginx-web", Type: "http", URL: "http://nginx-web:80/health", Interval: 60, Active: true,
	}}
	kumaIC, kumaRec := mockKumaReconcile(t, 1, monitors)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: false}, func(p Progress) {})

	if result.Run.Status != "completed" {
		t.Fatalf("expected completed, got %q (err=%q)", result.Run.Status, result.Run.ErrorMessage)
	}
	if result.Run.Updated != 2 {
		t.Errorf("expected 2 updates, got %d", result.Run.Updated)
	}
	if npmRec.puts != 1 {
		t.Errorf("expected 1 NPM update, got %d", npmRec.puts)
	}
	if npmRec.lastUpdate.ForwardPort != 8080 {
		t.Errorf("expected update to port 8080, got %d", npmRec.lastUpdate.ForwardPort)
	}
	if kumaRec.edits != 1 {
		t.Errorf("expected 1 Kuma edit, got %d", kumaRec.edits)
	}
	if kumaRec.lastEdit.MonitorID != 5 {
		t.Errorf("expected edit monitor 5, got %d", kumaRec.lastEdit.MonitorID)
	}
	if kumaRec.lastEdit.Payload["interval"] != 30 {
		t.Errorf("expected interval 30 in payload, got %v", kumaRec.lastEdit.Payload["interval"])
	}
	// Actions recorded as updated.
	actions := map[string]bool{}
	for _, c := range result.Changes {
		actions[c.Target] = c.Action == "updated"
	}
	if !actions["npm"] || !actions["kuma"] {
		t.Errorf("expected both targets updated, got %+v", result.Changes)
	}
}

func TestRunReconcileNoDrift(t *testing.T) {
	d := setupTestDB(t)
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	hosts := []npm.ProxyHost{{
		ID: 10, DomainNames: []string{"app.example.com", "www.app.example.com"},
		ForwardHost: "nginx-web", ForwardPort: 8080, ForwardScheme: "http", Enabled: true,
	}}
	monitors := []kuma.KumaMonitor{{
		ID: 5, Name: "nginx-web", Type: "http", URL: "http://nginx-web:80/health", Interval: 30, Active: true,
	}}
	npmIC, npmRec := mockNpmReconcile(t, 1, hosts)
	kumaIC, kumaRec := mockKumaReconcile(t, 1, monitors)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: false}, func(p Progress) {})

	if result.Run.Status != "completed" {
		t.Fatalf("expected completed, got %q (err=%q)", result.Run.Status, result.Run.ErrorMessage)
	}
	if result.Run.Added != 0 || result.Run.Updated != 0 {
		t.Errorf("expected zero changes, got added=%d updated=%d", result.Run.Added, result.Run.Updated)
	}
	if npmRec.posts != 0 || npmRec.puts != 0 {
		t.Errorf("expected no NPM writes, got posts=%d puts=%d", npmRec.posts, npmRec.puts)
	}
	if kumaRec.adds != 0 || kumaRec.edits != 0 {
		t.Errorf("expected no Kuma writes, got adds=%d edits=%d", kumaRec.adds, kumaRec.edits)
	}
	if len(result.Changes) != 0 {
		t.Errorf("expected no changes, got %+v", result.Changes)
	}
}

func TestRunReconcileOnlyServiceFilter(t *testing.T) {
	d := setupTestDB(t)
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create web link: %v", err)
	}
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "api", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create api link: %v", err)
	}
	npmIC, npmRec := mockNpmReconcile(t, 1, nil)
	kumaIC, kumaRec := mockKumaReconcile(t, 1, nil)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: false, OnlyService: "web"}, func(p Progress) {})

	if result.Run.Status != "completed" {
		t.Fatalf("expected completed, got %q (err=%q)", result.Run.Status, result.Run.ErrorMessage)
	}
	// Only "web" reconciled: one NPM + one Kuma target.
	if result.Run.Added != 2 {
		t.Errorf("expected 2 added (web only), got %d", result.Run.Added)
	}
	if result.Run.TotalServices != 1 {
		t.Errorf("expected 1 considered service, got %d", result.Run.TotalServices)
	}
	if npmRec.posts != 1 {
		t.Errorf("expected 1 NPM create, got %d", npmRec.posts)
	}
	if kumaRec.adds != 1 {
		t.Errorf("expected 1 Kuma add, got %d", kumaRec.adds)
	}
	for _, c := range result.Changes {
		if c.Service != "web" {
			t.Errorf("unexpected change for service %q", c.Service)
		}
	}
}

func TestRunReconcileUnlinkedServiceUntouched(t *testing.T) {
	d := setupTestDB(t)
	// Only "web" is linked; "api" in the compose file has no link.
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	npmIC, npmRec := mockNpmReconcile(t, 1, nil)
	kumaIC, kumaRec := mockKumaReconcile(t, 1, nil)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: false}, func(p Progress) {})

	if result.Run.Status != "completed" {
		t.Fatalf("expected completed, got %q (err=%q)", result.Run.Status, result.Run.ErrorMessage)
	}
	if result.Run.Added != 2 {
		t.Errorf("expected only linked web added (2 targets), got %d", result.Run.Added)
	}
	if npmRec.posts != 1 || kumaRec.adds != 1 {
		t.Errorf("expected exactly one NPM and one Kuma write, got npm=%d kuma=%d", npmRec.posts, kumaRec.adds)
	}
	if result.Run.TotalServices != 1 {
		t.Errorf("expected 1 considered service, got %d", result.Run.TotalServices)
	}
}

func TestRunReconcileFailedCreate(t *testing.T) {
	d := setupTestDB(t)
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1}); err != nil {
		t.Fatalf("create link: %v", err)
	}

	// NPM client whose create always fails.
	rec := &npmReconcileRecorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":   "test-jwt-token",
			"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/nginx/proxy-hosts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]npm.ProxyHost{})
		case http.MethodPost:
			rec.posts++
			http.Error(w, "create failed", http.StatusInternalServerError)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	npmIC := npm.InstanceClient{InstanceID: 1, Client: npm.NewClient(srv.URL, "user", "pass")}

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, nil, d,
		ReconcileOptions{DryRun: false}, func(p Progress) {})

	if result.Run.Status != "completed_with_errors" {
		t.Errorf("expected completed_with_errors, got %q", result.Run.Status)
	}
	if result.Run.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", result.Run.Failed)
	}
	if result.Run.Added != 0 {
		t.Errorf("expected 0 added, got %d", result.Run.Added)
	}
	if rec.posts != 1 {
		t.Errorf("expected 1 POST attempt, got %d", rec.posts)
	}
	if len(result.Changes) != 1 || result.Changes[0].Action != "error" {
		t.Errorf("expected 1 error change, got %+v", result.Changes)
	}
}

func TestRunReconcileNoLinks(t *testing.T) {
	d := setupTestDB(t)
	result := RunReconcile(context.Background(), writeReconcileCompose(t), nil, nil, d,
		ReconcileOptions{DryRun: false}, func(p Progress) {})
	if result.Run.Status != "completed" {
		t.Errorf("expected completed, got %q", result.Run.Status)
	}
	if result.Run.ErrorMessage != "no service links configured" {
		t.Errorf("unexpected message %q", result.Run.ErrorMessage)
	}
}

func TestRunReconcileOnlyServiceNotLinked(t *testing.T) {
	d := setupTestDB(t)
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	npmIC, _ := mockNpmReconcile(t, 1, nil)
	kumaIC, _ := mockKumaReconcile(t, 1, nil)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: false, OnlyService: "nosuch"}, func(p Progress) {})

	if result.Run.Status != "completed" {
		t.Errorf("expected completed, got %q", result.Run.Status)
	}
	if result.Run.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Run.Skipped)
	}
	if result.Run.Added != 0 {
		t.Errorf("expected no additions, got %d", result.Run.Added)
	}
}

// --- Pure helper tests ---

func TestParseFirstPort(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"80:80", 80},
		{"443:8443/tcp", 443},
		{"8080", 8080},
		{"8000-8005:80", 8000},
		{"", 0},
		{"junk", 0},
	}
	for _, c := range cases {
		if got := parseFirstPort(c.in); got != c.want {
			t.Errorf("parseFirstPort(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIntervalSeconds(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"30s", 30},
		{"1m", 60},
		{"500ms", 0},
		{"", 0},
		{"bogus", 0},
	}
	for _, c := range cases {
		if got := intervalSeconds(c.in); got != c.want {
			t.Errorf("intervalSeconds(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestDesiredNPMHost(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "nginx-web",
		Ports:         PortsRaw{"8080:80", "8443:443/tcp"},
		Labels: LabelsRaw{
			"synapse.domains": " app.example.com, www.app.example.com ",
			"synapse.scheme":  "https",
		},
	}
	cfg, ok := desiredNPMHost("web", svc)
	if !ok {
		t.Fatal("expected derivable host")
	}
	if cfg.ForwardHost != "nginx-web" || cfg.ForwardPort != 8080 || cfg.ForwardScheme != "https" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
	if len(cfg.DomainNames) != 2 || cfg.DomainNames[0] != "app.example.com" {
		t.Errorf("unexpected domains: %v", cfg.DomainNames)
	}

	// No domain label → not derivable.
	if _, ok := desiredNPMHost("web", ServiceDef{Ports: PortsRaw{"80:80"}}); ok {
		t.Error("expected not derivable without domain label")
	}
}

func TestDesiredNPMHostPortOverride(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "nginx-web",
		Labels:        LabelsRaw{"synapse.domain": "one.example.com", "synapse.port": "9443"},
	}
	cfg, ok := desiredNPMHost("web", svc)
	if !ok {
		t.Fatal("expected derivable")
	}
	if cfg.ForwardPort != 9443 {
		t.Errorf("expected label port 9443, got %d", cfg.ForwardPort)
	}
}

func TestDesiredMonitor(t *testing.T) {
	// Healthcheck URL → http monitor.
	svc := ServiceDef{
		ContainerName: "nginx-web",
		HealthCheck:   &HealthDef{Test: []any{"CMD", "curl", "-f", "http://localhost:80/health"}, Interval: "30s"},
	}
	mtype, url, container, interval := desiredMonitor("web", svc)
	if mtype != "http" || url != "http://nginx-web:80/health" || container != "" {
		t.Errorf("unexpected http monitor: type=%q url=%q container=%q", mtype, url, container)
	}
	if interval != 30 {
		t.Errorf("expected interval 30, got %d", interval)
	}

	// No healthcheck → docker monitor targeting container.
	svc = ServiceDef{ContainerName: "redis-svc"}
	mtype, url, container, interval = desiredMonitor("redis", svc)
	if mtype != "docker" || container != "redis-svc" || url != "" {
		t.Errorf("unexpected docker monitor: type=%q url=%q container=%q", mtype, url, container)
	}
	if interval != 60 {
		t.Errorf("expected default interval 60, got %d", interval)
	}
}

func TestNPMHostDrift(t *testing.T) {
	cfg := npm.ProxyHostCreate{
		DomainNames: []string{"a.example.com"}, ForwardHost: "web",
		ForwardPort: 8080, ForwardScheme: "http", Enabled: true,
	}
	live := npm.ProxyHost{
		DomainNames: []string{"a.example.com"}, ForwardHost: "web",
		ForwardPort: 8080, ForwardScheme: "http", Enabled: true,
	}
	if d := npmHostDrift(live, cfg); len(d) != 0 {
		t.Errorf("expected no drift, got %v", d)
	}

	live.ForwardPort = 80
	live.DomainNames = []string{"b.example.com"}
	live.ForwardScheme = "https"
	live.Enabled = false
	d := npmHostDrift(live, cfg)
	if len(d) != 4 {
		t.Errorf("expected 4 drifts, got %v", d)
	}
}

func TestMonitorDrift(t *testing.T) {
	live := kuma.KumaMonitor{ID: 1, Type: "http", URL: "http://web:80/h", Interval: 30}
	if d := monitorDrift(live, "http", "http://web:80/h", "", 30); len(d) != 0 {
		t.Errorf("expected no drift, got %v", d)
	}
	d := monitorDrift(live, "docker", "", "web", 60)
	if len(d) != 3 {
		t.Errorf("expected 3 drifts, got %v", d)
	}
	// Non-positive desired interval = no opinion.
	if d := monitorDrift(live, "http", "http://web:80/h", "", 0); len(d) != 0 {
		t.Errorf("expected no interval drift, got %v", d)
	}
}

func TestRunReconcileSkipsPausedMonitor(t *testing.T) {
	d := setupTestDB(t)
	if _, err := d.CreateServiceLink(&db.ServiceLink{ServiceName: "web", NPMInstanceID: 1, KumaInstanceID: 1}); err != nil {
		t.Fatalf("create link: %v", err)
	}
	npmIC, npmRec := mockNpmReconcile(t, 1, []npm.ProxyHost{{
		ID: 10, DomainNames: []string{"app.example.com", "www.app.example.com"},
		ForwardHost: "nginx-web", ForwardPort: 8080, ForwardScheme: "http", Enabled: true,
	}})
	monitors := []kuma.KumaMonitor{{
		ID: 5, Name: "nginx-web", Type: "http", URL: "http://nginx-web:80/health", Interval: 60, Active: false,
	}}
	kumaIC, kumaRec := mockKumaReconcile(t, 1, monitors)

	result := RunReconcile(context.Background(), writeReconcileCompose(t),
		[]npm.InstanceClient{npmIC}, []kuma.InstanceClient{kumaIC}, d,
		ReconcileOptions{DryRun: false}, func(p Progress) {})

	if result.Run.Skipped != 1 {
		t.Errorf("expected 1 skipped for paused monitor, got %d", result.Run.Skipped)
	}
	if kumaRec.edits != 0 {
		t.Errorf("paused monitor should not be edited, got %d edits", kumaRec.edits)
	}
	if npmRec.puts != 0 || npmRec.posts != 0 {
		t.Errorf("npm should not be drifted, got puts=%d posts=%d", npmRec.puts, npmRec.posts)
	}
	found := false
	for _, c := range result.Changes {
		if c.Target == "kuma" && c.Action == "skipped" && c.Detail == "paused" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected kuma skipped with detail paused, got %+v", result.Changes)
	}
	if result.Run.Updated != 0 || result.Run.Added != 0 {
		t.Errorf("expected no added/updated for paused, got added=%d updated=%d", result.Run.Added, result.Run.Updated)
	}
}

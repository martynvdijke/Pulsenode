package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"synapse/internal/db"
	"synapse/internal/kuma"
	"synapse/internal/npm"
)

//go:fix inline
func strPtr(s string) *string { return new(s) }

func TestParseHealthcheck_Nil(t *testing.T) {
	got := ParseHealthcheck("svc", ServiceDef{})
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestParseHealthcheck_NoTest(t *testing.T) {
	got := ParseHealthcheck("svc", ServiceDef{HealthCheck: &HealthDef{}})
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "my-web",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost:8080/health"},
		},
	}
	got := ParseHealthcheck("web", svc)
	want := "http://my-web:8080/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost_RootPath(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "my-web",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://127.0.0.1/"}, // root path
		},
	}
	got := ParseHealthcheck("web", svc)
	want := "http://my-web:80/"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost_DefaultPath(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "my-web",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost:8080"},
		},
	}
	got := ParseHealthcheck("web", svc)
	want := "http://my-web:8080/"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost_DefaultPort(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "my-web",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost/health"},
		},
	}
	got := ParseHealthcheck("web", svc)
	want := "http://my-web:80/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost_NoContainerName(t *testing.T) {
	svc := ServiceDef{
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost:3000/ready"},
		},
	}
	got := ParseHealthcheck("api", svc)
	want := "http://api:3000/ready"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost_QueryParams(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "svc-health",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost:5000/check?token=abc&format=json"},
		},
	}
	got := ParseHealthcheck("svc", svc)
	want := "http://svc-health:5000/check?token=abc&format=json"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost_DeepPath(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "app",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost:9000/api/v2/health"},
		},
	}
	got := ParseHealthcheck("app", svc)
	want := "http://app:9000/api/v2/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestParseHealthcheck_CMD_Curl_Localhost_UnderscorePath(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "my-svc",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost:8080/live_check"},
		},
	}
	got := ParseHealthcheck("svc", svc)
	want := "http://my-svc:8080/live_check"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// CMDSHELL with shell-wrapped curl
func TestParseHealthcheck_CMDSHELL_Curl(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "api-server",
		HealthCheck: &HealthDef{
			Test: []any{"CMD-SHELL", "curl -f http://localhost:8080/api/health || exit 1"},
		},
	}
	got := ParseHealthcheck("api", svc)
	want := "http://api-server:8080/api/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// String-format healthcheck (Docker-compose alternative syntax)
func TestParseHealthcheck_StringFormat(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "worker",
		HealthCheck: &HealthDef{
			Test: "curl -f http://localhost:9090/ready || exit 1",
		},
	}
	got := ParseHealthcheck("worker", svc)
	want := "http://worker:9090/ready"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// wget healthcheck
func TestParseHealthcheck_Wget(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "web",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "wget", "--spider", "http://localhost:8080/health"},
		},
	}
	got := ParseHealthcheck("web", svc)
	want := "http://web:8080/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// String wget healthcheck
func TestParseHealthcheck_Wget_String(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "monitor",
		HealthCheck: &HealthDef{
			Test: "wget --spider http://localhost:9090/ready 2>/dev/null",
		},
	}
	got := ParseHealthcheck("monitor", svc)
	want := "http://monitor:9090/ready"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// Non-localhost URL (service-name URL) should be returned as-is
func TestParseHealthcheck_ServiceNameURL(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "app",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://upstream:4000/health"},
		},
	}
	got := ParseHealthcheck("app", svc)
	want := "http://upstream:4000/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// Non-localhost URL without explicit port
func TestParseHealthcheck_ServiceNameURL_DefaultPort(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "app",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://upstream/health"},
		},
	}
	got := ParseHealthcheck("app", svc)
	want := "http://upstream:80/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// Network mode service: should use the referenced service name
func TestParseHealthcheck_NetworkModeService(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "sidecar",
		NetworkMode:   "service:proxy",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "curl", "-f", "http://localhost:8080/health"},
		},
	}
	got := ParseHealthcheck("my-service", svc)
	want := "http://proxy:8080/health"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// Healthcheck with no HTTP URL (e.g. pg_isready, redis-cli ping)
func TestParseHealthcheck_NoHTTP(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "pg",
		HealthCheck: &HealthDef{
			Test: []any{"CMD-SHELL", "pg_isready -U postgres"},
		},
	}
	got := ParseHealthcheck("db", svc)
	if got != "" {
		t.Errorf("expected empty for non-HTTP healthcheck, got %q", got)
	}
}

// Healthcheck with no HTTP URL (redis-ping)
func TestParseHealthcheck_NoHTTP_Redis(t *testing.T) {
	svc := ServiceDef{
		ContainerName: "redis",
		HealthCheck: &HealthDef{
			Test: []any{"CMD", "redis-cli", "ping"},
		},
	}
	got := ParseHealthcheck("redis", svc)
	if got != "" {
		t.Errorf("expected empty for non-HTTP healthcheck, got %q", got)
	}
}

// LoadServices tests
func TestLoadServices_FileNotFound(t *testing.T) {
	_, err := LoadServices("/nonexistent/path/docker-compose.yml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadServices_Success(t *testing.T) {
	services, err := LoadServices("../../testdata/docker-compose.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name         string
		wantContName string
		wantHasHC    bool
	}{
		{"web", "nginx-web", true},
		{"api", "myapp-api", true},
		{"db", "", true},
		{"redis", "cache-redis", true},
		{"worker", "", true}, // no container_name in compose
	}

	for _, tt := range tests {
		svc, ok := services[tt.name]
		if !ok {
			t.Errorf("service %q not found", tt.name)
			continue
		}
		if svc.ContainerName != tt.wantContName {
			t.Errorf("service %q container_name: expected %q, got %q", tt.name, tt.wantContName, svc.ContainerName)
		}
		if tt.wantHasHC && svc.HealthCheck == nil {
			t.Errorf("service %q: expected healthcheck, got nil", tt.name)
		}
	}
}

func TestParseHealthcheck_FromFile(t *testing.T) {
	services, err := LoadServices("../../testdata/docker-compose.yml")
	if err != nil {
		t.Fatalf("load services: %v", err)
	}

	tests := []struct {
		name string
		want string
	}{
		{"web", "http://nginx-web:80/health"},
		{"api", "http://myapp-api:8080/api/health"},
		{"db", ""},                             // pg_isready, no HTTP
		{"redis", ""},                          // redis-cli ping, no HTTP
		{"worker", "http://worker:9090/ready"}, // no container_name → uses service name
	}

	for _, tt := range tests {
		svc, ok := services[tt.name]
		if !ok {
			t.Errorf("service %q not found", tt.name)
			continue
		}
		got := ParseHealthcheck(tt.name, svc)
		if got != tt.want {
			t.Errorf("ParseHealthcheck(%q): expected %q, got %q", tt.name, tt.want, got)
		}
	}
}

// --- EnvironmentRaw tests ---

func TestEnvironmentRaw_UnmarshalYAML_Array(t *testing.T) {
	yamlContent := `env:
  - FOO=bar
  - BAZ=qux`
	var s struct {
		Env EnvironmentRaw `yaml:"env"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Env) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(s.Env))
	}
	if s.Env[0] != "FOO=bar" {
		t.Errorf("expected FOO=bar, got %q", s.Env[0])
	}
	if s.Env[1] != "BAZ=qux" {
		t.Errorf("expected BAZ=qux, got %q", s.Env[1])
	}
}

func TestEnvironmentRaw_UnmarshalYAML_Map(t *testing.T) {
	yamlContent := `env:
  FOO: bar
  BAZ: qux`
	var s struct {
		Env EnvironmentRaw `yaml:"env"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Env) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(s.Env))
	}
	// Map order is not guaranteed, so check both values are present
	vals := make(map[string]bool)
	for _, v := range s.Env {
		vals[v] = true
	}
	if !vals["FOO=bar"] {
		t.Error("expected FOO=bar in map output")
	}
	if !vals["BAZ=qux"] {
		t.Error("expected BAZ=qux in map output")
	}
}

func TestEnvironmentRaw_UnmarshalYAML_Empty(t *testing.T) {
	yamlContent := `env:`
	var s struct {
		Env EnvironmentRaw `yaml:"env"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Env != nil {
		t.Errorf("expected nil for empty env, got %v", s.Env)
	}
}

// --- ServiceDef new fields tests ---

func TestLoadServices_AllFieldsPopulated(t *testing.T) {
	services, err := LoadServices("../../testdata/docker-compose.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	web, ok := services["web"]
	if !ok {
		t.Fatal("service 'web' not found")
	}

	// Check image
	if web.Image != "nginx:alpine" {
		t.Errorf("expected image 'nginx:alpine', got %q", web.Image)
	}

	// Check ports
	if len(web.Ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(web.Ports))
	} else {
		if web.Ports[0] != "80:80" {
			t.Errorf("expected port '80:80', got %q", web.Ports[0])
		}
		if web.Ports[1] != "443:443/tcp" {
			t.Errorf("expected port '443:443/tcp', got %q", web.Ports[1])
		}
	}

	// Check environment (map format)
	if len(web.Environment) != 2 {
		t.Errorf("expected 2 env vars, got %d", len(web.Environment))
	}

	// Check volumes
	if len(web.Volumes) != 1 {
		t.Errorf("expected 1 volume, got %d", len(web.Volumes))
	} else if web.Volumes[0] != "./html:/usr/share/nginx/html:ro" {
		t.Errorf("unexpected volume: %q", web.Volumes[0])
	}

	// Check depends_on
	if len(web.DependsOn) != 1 || web.DependsOn[0] != "api" {
		t.Errorf("expected depends_on ['api'], got %v", web.DependsOn)
	}

	// Check labels
	if web.Labels == nil || web.Labels["app"] != "web" || web.Labels["tier"] != "frontend" {
		t.Errorf("unexpected labels: %v", web.Labels)
	}

	// Check restart
	if web.Restart != "always" {
		t.Errorf("expected restart 'always', got %q", web.Restart)
	}

	// Check healthcheck extended fields
	if web.HealthCheck == nil {
		t.Fatal("expected healthcheck on web")
	}
	if web.HealthCheck.Interval != "30s" {
		t.Errorf("expected interval '30s', got %q", web.HealthCheck.Interval)
	}
	if web.HealthCheck.Timeout != "10s" {
		t.Errorf("expected timeout '10s', got %q", web.HealthCheck.Timeout)
	}
	if web.HealthCheck.Retries != 3 {
		t.Errorf("expected retries 3, got %d", web.HealthCheck.Retries)
	}
	if web.HealthCheck.StartPeriod != "5s" {
		t.Errorf("expected start_period '5s', got %q", web.HealthCheck.StartPeriod)
	}

	// Check api environment (array format)
	api, ok := services["api"]
	if !ok {
		t.Fatal("service 'api' not found")
	}
	if len(api.Environment) != 6 {
		t.Errorf("expected 6 env vars for api, got %d", len(api.Environment))
	} else {
		if api.Environment[0] != "DB_HOST=db" {
			t.Errorf("expected 'DB_HOST=db', got %q", api.Environment[0])
		}
		if api.Environment[1] != "DB_PORT=5432" {
			t.Errorf("expected 'DB_PORT=5432', got %q", api.Environment[1])
		}
		if api.Environment[2] != "OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318" {
			t.Errorf("unexpected OTEL_EXPORTER_OTLP_ENDPOINT: %q", api.Environment[2])
		}
		if api.Environment[3] != "OTEL_EXPORTER_OTLP_PROTOCOL=grpc" {
			t.Errorf("unexpected OTEL_EXPORTER_OTLP_PROTOCOL: %q", api.Environment[3])
		}
	}

	// Check api depends_on
	if len(api.DependsOn) != 2 {
		t.Errorf("expected 2 depends_on for api, got %d", len(api.DependsOn))
	}

	// Check worker fields
	worker, ok := services["worker"]
	if !ok {
		t.Fatal("service 'worker' not found")
	}
	if worker.Entrypoint != "/entrypoint.sh" {
		t.Errorf("expected entrypoint '/entrypoint.sh', got %q", worker.Entrypoint)
	}
	if worker.User != "nobody" {
		t.Errorf("expected user 'nobody', got %q", worker.User)
	}
	if worker.WorkingDir != "/app" {
		t.Errorf("expected working_dir '/app', got %q", worker.WorkingDir)
	}

	// Check redis command
	redis, ok := services["redis"]
	if !ok {
		t.Fatal("service 'redis' not found")
	}
	if redis.Command != "redis-server --appendonly yes" {
		t.Errorf("expected command 'redis-server --appendonly yes', got %q", redis.Command)
	}
}

func TestLoadServices_MinimalFields(t *testing.T) {
	yamlContent := `
services:
  minimal:
    image: alpine:latest
`
	var c Compose
	if err := yaml.Unmarshal([]byte(yamlContent), &c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	svc, ok := c.Services["minimal"]
	if !ok {
		t.Fatal("service 'minimal' not found")
	}
	if svc.Image != "alpine:latest" {
		t.Errorf("expected image 'alpine:latest', got %q", svc.Image)
	}
	// Optional fields should be zero-valued
	if svc.Ports != nil {
		t.Errorf("expected nil ports, got %v", svc.Ports)
	}
	if svc.Environment != nil {
		t.Errorf("expected nil environment, got %v", svc.Environment)
	}
	if svc.HealthCheck != nil {
		t.Errorf("expected nil healthcheck, got %v", svc.HealthCheck)
	}
	if svc.Restart != "" {
		t.Errorf("expected empty restart, got %q", svc.Restart)
	}
}

func TestLoadServices_PortsWithProtocols(t *testing.T) {
	yamlContent := `
services:
  web:
    image: nginx
    ports:
      - "80:80"
      - "443:443/tcp"
      - "3000-3005:3000-3005/udp"
`
	var c Compose
	if err := yaml.Unmarshal([]byte(yamlContent), &c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	svc := c.Services["web"]
	if len(svc.Ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(svc.Ports))
	}
	if svc.Ports[0] != "80:80" {
		t.Errorf("expected '80:80', got %q", svc.Ports[0])
	}
	if svc.Ports[1] != "443:443/tcp" {
		t.Errorf("expected '443:443/tcp', got %q", svc.Ports[1])
	}
	if svc.Ports[2] != "3000-3005:3000-3005/udp" {
		t.Errorf("expected '3000-3005:3000-3005/udp', got %q", svc.Ports[2])
	}
}

func TestLoadServices_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/invalid.yml"
	if err := os.WriteFile(tmpFile, []byte("services:\n  web:\n    image: nginx\n  invalid_yaml: ["), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	_, err := LoadServices(tmpFile)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// --- ServiceInfo JSON serialization tests ---

func TestServiceInfo_JSON_OmitEmpty(t *testing.T) {
	info := ServiceInfo{
		Name:          "test",
		ContainerName: "test-container",
		MonitorType:   "docker",
	}
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Optional fields should be omitted
	if _, ok := decoded["image"]; ok {
		t.Error("expected image to be omitted")
	}
	if _, ok := decoded["ports"]; ok {
		t.Error("expected ports to be omitted")
	}
	if _, ok := decoded["healthcheck"]; ok {
		t.Error("expected healthcheck to be omitted")
	}
	// Required fields should be present
	if decoded["name"] != "test" {
		t.Errorf("expected name 'test', got %v", decoded["name"])
	}
}

func TestServiceInfo_JSON_AllFields(t *testing.T) {
	info := ServiceInfo{
		Name:          "web",
		ContainerName: "nginx-web",
		MonitorType:   "http",
		URL:           "http://nginx-web:80/health",
		Image:         "nginx:alpine",
		Ports:         []string{"80:80", "443:443/tcp"},
		Environment:   []string{"FOO=bar"},
		Volumes:       []string{"./html:/usr/share/nginx/html:ro"},
		DependsOn:     []string{"api"},
		Labels:        map[string]string{"app": "web"},
		Restart:       "always",
		Command:       "",
		Entrypoint:    "",
		User:          "nobody",
		WorkingDir:    "/app",
		HealthCheck: &HealthCheckInfo{
			Test:        []any{"CMD", "curl", "-f", "http://localhost:80/health"},
			Interval:    "30s",
			Timeout:     "10s",
			Retries:     3,
			StartPeriod: "5s",
		},
	}
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["image"] != "nginx:alpine" {
		t.Errorf("expected image 'nginx:alpine', got %v", decoded["image"])
	}
	ports := decoded["ports"].([]interface{})
	if len(ports) != 2 || ports[0] != "80:80" {
		t.Errorf("unexpected ports: %v", ports)
	}
	hc := decoded["healthcheck"].(map[string]interface{})
	if hc["interval"] != "30s" {
		t.Errorf("expected healthcheck interval '30s', got %v", hc["interval"])
	}
	if hc["retries"] != float64(3) {
		t.Errorf("expected retries 3, got %v", hc["retries"])
	}
}

// Test that the extractTestString helper handles all test types
func TestExtractTestString(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"nil", nil, ""},
		{"string", "curl -f http://localhost:8080/health", "curl -f http://localhost:8080/health"},
		{"[]any", []any{"CMD", "curl", "-f", "http://localhost:8080/health"}, "CMD curl -f http://localhost:8080/health"},
		{"int", 42, ""},
	}

	for _, tt := range tests {
		got := extractTestString(tt.input)
		if got != tt.want {
			t.Errorf("extractTestString(%s): expected %q, got %q", tt.name, tt.want, got)
		}
	}
}

// --- LabelsRaw tests ---

func TestLabelsRaw_UnmarshalYAML_Map(t *testing.T) {
	yamlContent := `labels:
  app: web
  tier: frontend`
	var s struct {
		Labels LabelsRaw `yaml:"labels"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(s.Labels))
	}
	if s.Labels["app"] != "web" {
		t.Errorf("expected app=web, got %q", s.Labels["app"])
	}
	if s.Labels["tier"] != "frontend" {
		t.Errorf("expected tier=frontend, got %q", s.Labels["tier"])
	}
}

func TestLabelsRaw_UnmarshalYAML_Array(t *testing.T) {
	yamlContent := `labels:
  - app=web
  - tier=frontend`
	var s struct {
		Labels LabelsRaw `yaml:"labels"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(s.Labels))
	}
	if s.Labels["app"] != "web" {
		t.Errorf("expected app=web, got %q", s.Labels["app"])
	}
	if s.Labels["tier"] != "frontend" {
		t.Errorf("expected tier=frontend, got %q", s.Labels["tier"])
	}
}

// --- PortsRaw tests ---

func TestPortsRaw_UnmarshalYAML_ShortSyntax(t *testing.T) {
	yamlContent := `ports:
  - "80:80"
  - "443:443/tcp"`
	var s struct {
		Ports PortsRaw `yaml:"ports"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(s.Ports))
	}
	if s.Ports[0] != "80:80" {
		t.Errorf("expected '80:80', got %q", s.Ports[0])
	}
	if s.Ports[1] != "443:443/tcp" {
		t.Errorf("expected '443:443/tcp', got %q", s.Ports[1])
	}
}

func TestPortsRaw_UnmarshalYAML_LongSyntax(t *testing.T) {
	yamlContent := `ports:
  - published: 8080
    target: 8080
  - published: 443
    target: 8443
    protocol: tcp`
	var s struct {
		Ports PortsRaw `yaml:"ports"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(s.Ports))
	}
	if s.Ports[0] != "8080:8080" {
		t.Errorf("expected '8080:8080', got %q", s.Ports[0])
	}
	if s.Ports[1] != "443:8443/tcp" {
		t.Errorf("expected '443:8443/tcp', got %q", s.Ports[1])
	}
}

// --- VolumesRaw tests ---

func TestVolumesRaw_UnmarshalYAML_ShortSyntax(t *testing.T) {
	yamlContent := `volumes:
  - ./html:/usr/share/nginx/html:ro
  - pgdata:/var/lib/postgresql/data`
	var s struct {
		Volumes VolumesRaw `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Volumes) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(s.Volumes))
	}
	if s.Volumes[0] != "./html:/usr/share/nginx/html:ro" {
		t.Errorf("expected './html:/usr/share/nginx/html:ro', got %q", s.Volumes[0])
	}
	if s.Volumes[1] != "pgdata:/var/lib/postgresql/data" {
		t.Errorf("expected 'pgdata:/var/lib/postgresql/data', got %q", s.Volumes[1])
	}
}

func TestVolumesRaw_UnmarshalYAML_LongSyntax(t *testing.T) {
	yamlContent := `volumes:
  - type: bind
    source: ./html
    target: /usr/share/nginx/html
  - type: volume
    source: pgdata
    target: /var/lib/postgresql/data`
	var s struct {
		Volumes VolumesRaw `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Volumes) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(s.Volumes))
	}
	if s.Volumes[0] != "./html:/usr/share/nginx/html" {
		t.Errorf("expected './html:/usr/share/nginx/html', got %q", s.Volumes[0])
	}
	if s.Volumes[1] != "pgdata:/var/lib/postgresql/data" {
		t.Errorf("expected 'pgdata:/var/lib/postgresql/data', got %q", s.Volumes[1])
	}
}

// --- DependsOnRaw tests ---

func TestDependsOnRaw_UnmarshalYAML_Array(t *testing.T) {
	yamlContent := `depends_on:
  - db
  - redis`
	var s struct {
		DependsOn DependsOnRaw `yaml:"depends_on"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.DependsOn) != 2 {
		t.Fatalf("expected 2 depends_on, got %d", len(s.DependsOn))
	}
	if s.DependsOn[0] != "db" {
		t.Errorf("expected 'db', got %q", s.DependsOn[0])
	}
	if s.DependsOn[1] != "redis" {
		t.Errorf("expected 'redis', got %q", s.DependsOn[1])
	}
}

func TestDependsOnRaw_UnmarshalYAML_Map(t *testing.T) {
	yamlContent := `depends_on:
  db:
    condition: service_healthy
  redis:
    condition: service_started`
	var s struct {
		DependsOn DependsOnRaw `yaml:"depends_on"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.DependsOn) != 2 {
		t.Fatalf("expected 2 depends_on, got %d", len(s.DependsOn))
	}
	// Map keys are extracted; order is not guaranteed
	depMap := make(map[string]bool)
	for _, d := range s.DependsOn {
		depMap[d] = true
	}
	if !depMap["db"] {
		t.Error("expected 'db' in depends_on")
	}
	if !depMap["redis"] {
		t.Error("expected 'redis' in depends_on")
	}
}

// --- CommandRaw tests ---

func TestCommandRaw_UnmarshalYAML_String(t *testing.T) {
	yamlContent := `command: redis-server --appendonly yes`
	var s struct {
		Command CommandRaw `yaml:"command"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(s.Command) != "redis-server --appendonly yes" {
		t.Errorf("expected 'redis-server --appendonly yes', got %q", string(s.Command))
	}
}

func TestCommandRaw_UnmarshalYAML_Array(t *testing.T) {
	yamlContent := `command: ["redis-server", "--appendonly", "yes"]`
	var s struct {
		Command CommandRaw `yaml:"command"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(s.Command) != "redis-server --appendonly yes" {
		t.Errorf("expected 'redis-server --appendonly yes', got %q", string(s.Command))
	}
}

func TestCommandRaw_UnmarshalYAML_Empty(t *testing.T) {
	yamlContent := `command: []`
	var s struct {
		Command CommandRaw `yaml:"command"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(s.Command) != "" {
		t.Errorf("expected empty string, got %q", string(s.Command))
	}
}

// --- EntrypointRaw tests ---

func TestEntrypointRaw_UnmarshalYAML_String(t *testing.T) {
	yamlContent := `entrypoint: /entrypoint.sh`
	var s struct {
		Entrypoint EntrypointRaw `yaml:"entrypoint"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(s.Entrypoint) != "/entrypoint.sh" {
		t.Errorf("expected '/entrypoint.sh', got %q", string(s.Entrypoint))
	}
}

func TestEntrypointRaw_UnmarshalYAML_Array(t *testing.T) {
	yamlContent := `entrypoint: ["/entrypoint.sh", "--flag"]`
	var s struct {
		Entrypoint EntrypointRaw `yaml:"entrypoint"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(s.Entrypoint) != "/entrypoint.sh --flag" {
		t.Errorf("expected '/entrypoint.sh --flag', got %q", string(s.Entrypoint))
	}
}

// --- Integration: Full compose with alternate formats ---

func TestLoadServices_AlternateFormats(t *testing.T) {
	yamlContent := `
services:
  web:
    image: nginx
    ports:
      - published: 8080
        target: 80
    volumes:
      - type: bind
        source: ./html
        target: /usr/share/nginx/html
    depends_on:
      api:
        condition: service_healthy
    labels:
      - app=web
      - tier=frontend
    command: ["nginx", "-g", "daemon off;"]
    entrypoint: ["/docker-entrypoint.sh"]

  api:
    image: myapp
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
    depends_on:
      - db
    labels:
      app: api
      tier: backend
    command: npm start
    entrypoint: ""
`
	var c Compose
	if err := yaml.Unmarshal([]byte(yamlContent), &c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	web, ok := c.Services["web"]
	if !ok {
		t.Fatal("service 'web' not found")
	}

	// Check web ports (long syntax)
	if len(web.Ports) != 1 || web.Ports[0] != "8080:80" {
		t.Errorf("expected ['8080:80'], got %v", web.Ports)
	}

	// Check web volumes (long syntax)
	if len(web.Volumes) != 1 || web.Volumes[0] != "./html:/usr/share/nginx/html" {
		t.Errorf("expected ['./html:/usr/share/nginx/html'], got %v", web.Volumes)
	}

	// Check web depends_on (map syntax)
	if len(web.DependsOn) != 1 || web.DependsOn[0] != "api" {
		t.Errorf("expected depends_on ['api'], got %v", web.DependsOn)
	}

	// Check web labels (array syntax)
	if web.Labels == nil || web.Labels["app"] != "web" {
		t.Errorf("expected labels {app: web}, got %v", web.Labels)
	}

	// Check web command (array syntax)
	if string(web.Command) != "nginx -g daemon off;" {
		t.Errorf("expected 'nginx -g daemon off;', got %q", string(web.Command))
	}

	// Check web entrypoint (array syntax)
	if string(web.Entrypoint) != "/docker-entrypoint.sh" {
		t.Errorf("expected '/docker-entrypoint.sh', got %q", string(web.Entrypoint))
	}

	// Check api fields (mix of traditional and alternate)
	api, ok := c.Services["api"]
	if !ok {
		t.Fatal("service 'api' not found")
	}

	if len(api.Ports) != 1 || api.Ports[0] != "8080:8080" {
		t.Errorf("expected ['8080:8080'], got %v", api.Ports)
	}

	if len(api.Volumes) != 1 || api.Volumes[0] != "./data:/app/data" {
		t.Errorf("expected ['./data:/app/data'], got %v", api.Volumes)
	}

	if len(api.DependsOn) != 1 || api.DependsOn[0] != "db" {
		t.Errorf("expected depends_on ['db'], got %v", api.DependsOn)
	}

	if api.Labels == nil || api.Labels["app"] != "api" {
		t.Errorf("expected labels {app: api}, got %v", api.Labels)
	}

	if string(api.Command) != "npm start" {
		t.Errorf("expected 'npm start', got %q", string(api.Command))
	}

	if string(api.Entrypoint) != "" {
		t.Errorf("expected empty entrypoint, got %q", string(api.Entrypoint))
	}
}

// --- multi-Kuma fan-out tests ---

// setupTestDB mirrors the helper in internal/db/db_test.go.
func setupTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// mockKumaClient sets up per-client hooks for Kuma Socket.IO methods
// to return canned data instead of connecting to a real Kuma instance.
// addCalls counts AddMonitorViaSocketIO invocations. existingMonitors is
// the list returned by QueryMonitorsViaSocketIO (simulating pre-existing
// monitors). Each client gets its own hooks so multiple clients can have
// independent behavior in the same test.
func mockKumaClient(t *testing.T, instanceID int, addCalls *int32, existingMonitors []kuma.KumaMonitor) kuma.InstanceClient {
	t.Helper()

	c := kuma.NewClient("http://kuma-mock.invalid")
	c.SetTestHooks(&kuma.ClientTestHooks{
		QueryMonitors: func() ([]kuma.KumaMonitor, error) {
			return existingMonitors, nil
		},
		AddMonitor: func(monitorType, name, url, dockerContainer string, dockerHostID int) (int, error) {
			if addCalls != nil {
				atomic.AddInt32(addCalls, 1)
			}
			return 1, nil
		},
	})
	return kuma.InstanceClient{InstanceID: instanceID, Client: c}
}

func TestRunDockerSyncFanOut(t *testing.T) {
	d := setupTestDB(t)

	var add1, add2 int32
	c1 := mockKumaClient(t, 1, &add1, nil)
	c2 := mockKumaClient(t, 2, &add2, nil)

	run := RunDockerSync(context.Background(), "../../testdata/docker-compose.yml", []kuma.InstanceClient{c1, c2}, d, func(p Progress) {})

	if run.Status != "completed" {
		t.Errorf("expected status completed, got %q (err=%q)", run.Status, run.ErrorMessage)
	}
	if run.Added == 0 {
		t.Error("expected some monitors added")
	}
	// Both instances should have received AddMonitor calls.
	if atomic.LoadInt32(&add1) == 0 {
		t.Error("instance 1 received no AddMonitor calls")
	}
	if atomic.LoadInt32(&add2) == 0 {
		t.Error("instance 2 received no AddMonitor calls")
	}
	if atomic.LoadInt32(&add1) != atomic.LoadInt32(&add2) {
		t.Errorf("fan-out should add equally to both instances: %d vs %d", add1, add2)
	}

	// DB should have monitors for both instance ids.
	mons, _ := d.GetMonitors()
	var inst1, inst2 int
	for _, m := range mons {
		if m.KumaInstanceID == 1 {
			inst1++
		}
		if m.KumaInstanceID == 2 {
			inst2++
		}
	}
	if inst1 == 0 || inst2 == 0 {
		t.Errorf("expected monitors for both instances, got inst1=%d inst2=%d", inst1, inst2)
	}
	if inst1 != inst2 {
		t.Errorf("expected equal monitors per instance, got %d vs %d", inst1, inst2)
	}
}

func TestRunDockerSyncEmptyClients(t *testing.T) {
	d := setupTestDB(t)

	run := RunDockerSync(context.Background(), "../../testdata/docker-compose.yml", nil, d, func(p Progress) {})

	if run.Status != "error" {
		t.Errorf("expected status error, got %q", run.Status)
	}
	if run.ErrorMessage == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRunDockerSyncSkipsExisting(t *testing.T) {
	d := setupTestDB(t)

	// Pre-populate the mock with an existing monitor named "nginx-web"
	// (the displayName of the "web" service in testdata/docker-compose.yml).
	existing := []kuma.KumaMonitor{{ID: 100, Name: "nginx-web", Type: "http"}}
	var addCalls int32
	c := mockKumaClient(t, 1, &addCalls, existing)

	run := RunDockerSync(context.Background(), "../../testdata/docker-compose.yml", []kuma.InstanceClient{c}, d, func(p Progress) {})

	if run.Status != "completed" {
		t.Errorf("expected completed, got %q (err=%q)", run.Status, run.ErrorMessage)
	}
	if run.Skipped < 1 {
		t.Errorf("expected at least 1 skipped (nginx-web), got %d", run.Skipped)
	}
	// 6 services total (including otel-collector), 1 skipped → 5 added.
	if atomic.LoadInt32(&addCalls) != 5 {
		t.Errorf("expected 5 AddMonitor calls (6 services - 1 existing), got %d", addCalls)
	}
}

func TestGetDockerServicesWithStatusMultiInstance(t *testing.T) {
	// Client 1 has "nginx-web" in Kuma; client 2 has nothing.
	c1 := mockKumaClient(t, 1, nil, []kuma.KumaMonitor{{ID: 100, Name: "nginx-web", Type: "http"}})
	c2 := mockKumaClient(t, 2, nil, nil)

	services, err := GetDockerServicesWithStatus(context.Background(), "../../testdata/docker-compose.yml", []kuma.InstanceClient{c1, c2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(services) == 0 {
		t.Fatal("expected services, got none")
	}

	foundNginx := false
	for _, s := range services {
		if s.ContainerName == "nginx-web" {
			foundNginx = true
			if !s.InKuma {
				t.Errorf("nginx-web should be InKuma (present in instance 1)")
			}
		} else {
			if s.InKuma {
				t.Errorf("service %q should not be InKuma", s.ContainerName)
			}
		}
	}
	if !foundNginx {
		t.Fatal("nginx-web service not found in result")
	}
}

func TestGetDockerServicesWithStatusEmptyClients(t *testing.T) {
	services, err := GetDockerServicesWithStatus(context.Background(), "../../testdata/docker-compose.yml", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(services) == 0 {
		t.Fatal("expected services, got none")
	}
	for _, s := range services {
		if s.InKuma {
			t.Errorf("service %q should not be InKuma with no clients", s.ContainerName)
		}
	}
}

// --- NPM sync tests ---

// mockNpmClient starts an httptest server with JWT auth and NPM proxy host
// endpoints, and returns an npm.InstanceClient backed by it.
func mockNpmClient(t *testing.T, instanceID int, entries []npm.ProxyEntry) npm.InstanceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":   "test-jwt-token",
			"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/nginx/proxy-hosts", func(w http.ResponseWriter, r *http.Request) {
		// Convert ProxyEntry to flattened ProxyHost response format matching the
		// real NPM REST API (no nested forwarding object, no container field).
		hosts := make([]npm.ProxyHost, len(entries))
		for i, e := range entries {
			hosts[i] = npm.ProxyHost{
				ID:            i + 1,
				DomainNames:   []string{e.CNAME},
				ForwardHost:   e.Host,
				ForwardPort:   e.Port,
				ForwardScheme: e.Protocol,
				Enabled:       true,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hosts)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return npm.InstanceClient{
		InstanceID: instanceID,
		Client:     npm.NewClient(srv.URL, "user", "pass"),
	}
}

// mockNpmClientFailing returns an npm.InstanceClient whose proxy-hosts
// endpoint always fails (e.g. unreachable/unauthorized NPM instance).
func mockNpmClientFailing(t *testing.T, instanceID int) npm.InstanceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":   "test-jwt-token",
			"expires": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/nginx/proxy-hosts", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return npm.InstanceClient{
		InstanceID: instanceID,
		Client:     npm.NewClient(srv.URL, "user", "pass"),
	}
}

func TestGetNPMProxyEntries(t *testing.T) {
	c1 := mockNpmClient(t, 1, []npm.ProxyEntry{
		{CNAME: "example.com", Container: "web", Host: "10.0.0.1", Port: 80, Protocol: "http"},
		{CNAME: "app.example.com", Container: "app", Host: "10.0.0.2", Port: 8080, Protocol: "http"},
	})
	c2 := mockNpmClient(t, 2, []npm.ProxyEntry{
		{CNAME: "example.com", Container: "web-old", Host: "10.0.0.3", Port: 80, Protocol: "http"},
		{CNAME: "internal.example.com", Container: "db", Host: "10.0.0.4", Port: 5432, Protocol: "tcp"},
	})

	entries, err := GetNPMProxyEntries([]npm.InstanceClient{c1, c2})
	if err != nil {
		t.Fatalf("GetNPMProxyEntries: %v", err)
	}

	// Dedup: example.com should come from instance 1 (first in iteration order)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (deduped), got %d", len(entries))
	}

	found := map[string]int{}
	for _, e := range entries {
		found[e.CNAME] = e.SourceInstanceID
	}
	if found["example.com"] != 1 {
		t.Errorf("example.com should be from instance 1 (first wins), got instance %d", found["example.com"])
	}
	if found["app.example.com"] != 1 {
		t.Errorf("app.example.com should be from instance 1, got instance %d", found["app.example.com"])
	}
	if found["internal.example.com"] != 2 {
		t.Errorf("internal.example.com should be from instance 2, got instance %d", found["internal.example.com"])
	}
}

func TestGetNPMProxyEntriesPartialFailure(t *testing.T) {
	// Instance 1 fails, instance 2 succeeds: partial results + aggregate error.
	c1 := mockNpmClientFailing(t, 1)
	c2 := mockNpmClient(t, 2, []npm.ProxyEntry{
		{CNAME: "app.example.com", Container: "app", Host: "10.0.0.2", Port: 8080, Protocol: "http"},
	})

	entries, err := GetNPMProxyEntries([]npm.InstanceClient{c1, c2})
	if err == nil {
		t.Fatal("expected aggregate error for failing instance 1")
	}
	if !strings.Contains(err.Error(), "instance 1") {
		t.Errorf("expected error to mention instance 1, got %q", err.Error())
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 partial entry (from instance 2), got %d", len(entries))
	}
	if entries[0].CNAME != "app.example.com" || entries[0].SourceInstanceID != 2 {
		t.Errorf("expected app.example.com from instance 2, got %+v", entries[0])
	}
}

func TestGetNPMProxyEntriesAllFail(t *testing.T) {
	// All instances fail: empty result + aggregate error.
	c1 := mockNpmClientFailing(t, 1)
	c2 := mockNpmClientFailing(t, 2)

	entries, err := GetNPMProxyEntries([]npm.InstanceClient{c1, c2})
	if err == nil {
		t.Fatal("expected aggregate error")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries when all instances fail, got %d", len(entries))
	}
}

func TestGetNPMProxyEntriesEmpty(t *testing.T) {
	entries, err := GetNPMProxyEntries(nil)
	if err != nil {
		t.Fatalf("GetNPMProxyEntries nil: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nil clients, got %d", len(entries))
	}

	entries, err = GetNPMProxyEntries([]npm.InstanceClient{})
	if err != nil {
		t.Fatalf("GetNPMProxyEntries empty: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty clients, got %d", len(entries))
	}
}

func TestGetNPMProxiesWithStatus(t *testing.T) {
	// Two NPM clients: c1 has "example.com", c2 has "api.example.com" (also in Kuma).
	c1 := mockNpmClient(t, 1, []npm.ProxyEntry{
		{CNAME: "example.com", Container: "web", Host: "10.0.0.1", Port: 80, Protocol: "http"},
	})
	c2 := mockNpmClient(t, 2, []npm.ProxyEntry{
		{CNAME: "api.example.com", Container: "api", Host: "10.0.0.2", Port: 8080, Protocol: "http"},
	})

	// One Kuma client with "api.example.com" monitor.
	kumaClient := mockKumaClient(t, 1, nil, []kuma.KumaMonitor{{ID: 42, Name: "api.example.com", Type: "http"}})

	proxies, err := GetNPMProxiesWithStatus(context.Background(), []npm.InstanceClient{c1, c2}, []kuma.InstanceClient{kumaClient})
	if err != nil {
		t.Fatalf("GetNPMProxiesWithStatus: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}

	proxyMap := map[string]bool{}
	instanceMap := map[string]int{}
	for _, p := range proxies {
		proxyMap[p.CNAME] = p.InKuma
		instanceMap[p.CNAME] = p.SourceInstanceID
	}

	if proxyMap["example.com"] != false {
		t.Errorf("example.com should not be InKuma (not in any Kuma instance)")
	}
	if proxyMap["api.example.com"] != true {
		t.Errorf("api.example.com should be InKuma (present in Kuma instance)")
	}
	if instanceMap["api.example.com"] != 2 {
		t.Errorf("api.example.com should have SourceInstanceID 2, got %d", instanceMap["api.example.com"])
	}
}

func TestGetNPMProxiesWithStatusEmptyClients(t *testing.T) {
	// No NPM clients should return empty.
	proxies, err := GetNPMProxiesWithStatus(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetNPMProxiesWithStatus nil: %v", err)
	}
	if len(proxies) != 0 {
		t.Errorf("expected 0 proxies for nil clients, got %d", len(proxies))
	}
}

func TestGetNPMProxiesWithStatusPartialFailure(t *testing.T) {
	// Instance 1 fails, instance 2 succeeds: partial proxies + aggregate error.
	c1 := mockNpmClientFailing(t, 1)
	c2 := mockNpmClient(t, 2, []npm.ProxyEntry{
		{CNAME: "api.example.com", Container: "api", Host: "10.0.0.2", Port: 8080, Protocol: "http"},
	})
	kumaClient := mockKumaClient(t, 1, nil, []kuma.KumaMonitor{{ID: 42, Name: "api.example.com", Type: "http"}})

	proxies, err := GetNPMProxiesWithStatus(context.Background(), []npm.InstanceClient{c1, c2}, []kuma.InstanceClient{kumaClient})
	if err == nil {
		t.Fatal("expected aggregate error for failing instance 1")
	}
	if len(proxies) != 1 {
		t.Fatalf("expected 1 partial proxy (from instance 2), got %d", len(proxies))
	}
	if proxies[0].CNAME != "api.example.com" || !proxies[0].InKuma || proxies[0].SourceInstanceID != 2 {
		t.Errorf("expected api.example.com InKuma from instance 2, got %+v", proxies[0])
	}
}

func TestRunNPMSync(t *testing.T) {
	d := setupTestDB(t)

	npmClient := mockNpmClient(t, 1, []npm.ProxyEntry{
		{CNAME: "synced.example.com", Container: "synced", Host: "10.0.0.1", Port: 80, Protocol: "http"},
	})

	var kumaAddCalls int32
	kumaClient := mockKumaClient(t, 1, &kumaAddCalls, nil)

	run := RunNPMSync(context.Background(), []npm.InstanceClient{npmClient}, []kuma.InstanceClient{kumaClient}, d, func(p Progress) {})

	if run.Status != "completed" {
		t.Errorf("expected status completed, got %q (err=%q)", run.Status, run.ErrorMessage)
	}
	if run.Added == 0 {
		t.Error("expected at least 1 monitor added")
	}
	if atomic.LoadInt32(&kumaAddCalls) < 1 {
		t.Errorf("expected at least 1 AddMonitor call, got %d", kumaAddCalls)
	}
}

func TestRunNPMSyncEmptyClients(t *testing.T) {
	d := setupTestDB(t)

	run := RunNPMSync(context.Background(), nil, nil, d, func(p Progress) {})
	if run.Status != "error" {
		t.Errorf("expected status error, got %q", run.Status)
	}
	if run.ErrorMessage == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRunNPMSyncSkipsExisting(t *testing.T) {
	d := setupTestDB(t)

	npmClient := mockNpmClient(t, 1, []npm.ProxyEntry{
		{CNAME: "existing.example.com", Container: "existing", Host: "10.0.0.1", Port: 80, Protocol: "http"},
	})

	var kumaAddCalls int32
	// Kuma already has a monitor for "existing.example.com"
	kumaClient := mockKumaClient(t, 1, &kumaAddCalls, []kuma.KumaMonitor{{ID: 100, Name: "existing.example.com", Type: "http"}})

	run := RunNPMSync(context.Background(), []npm.InstanceClient{npmClient}, []kuma.InstanceClient{kumaClient}, d, func(p Progress) {})

	if run.Status != "completed" {
		t.Errorf("expected completed, got %q (err=%q)", run.Status, run.ErrorMessage)
	}
	if run.Skipped < 1 {
		t.Errorf("expected at least 1 skipped (existing), got %d", run.Skipped)
	}
	if atomic.LoadInt32(&kumaAddCalls) != 0 {
		t.Errorf("expected 0 AddMonitor calls (all existing), got %d", kumaAddCalls)
	}
}

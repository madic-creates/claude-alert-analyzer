# Design Review: claude-alert-analyzer

**Date:** 2026-04-16
**Scope:** Comprehensive design review covering architecture, security, CI/CD, observability, concurrency, and operational concerns.
**Baseline commit:** `6a7b33a`
**Overall score:** 7.5/10

## Current State

- 5,664 lines of Go (2,153 production, 3,511 test)
- 188 tests across 3 packages, all passing
- Test coverage: `internal/shared` ~95%, `internal/k8s` ~95%, `internal/checkmk` ~80%, `cmd/*/main.go` 0%
- Clean dependency graph, no circular imports
- Strong security baseline (constant-time auth, MaxBytesReader, LimitReader, secret redaction, SSH shell-quoting, hostname validation, known_hosts enforcement)

## 1. Architecture: Shared Server Scaffold + Pipeline Extraction (P0/P1)

### Problem

Both `main.go` files share ~120 lines of structurally identical code:
- `envOrDefault` (identical)
- `buildPublishers` (identical)
- Worker pool setup, HTTP server config, signal handling, graceful shutdown (structurally identical)

`processAlert` in both binaries contains the core orchestration logic (context gathering, Claude API, publish, cooldown-clear-on-failure, metrics) but is unexported in `main` with 0% test coverage.

### Design

#### 1a. `internal/shared/server.go` — Shared server scaffold

```go
type ServerConfig struct {
    Port         string
    ReadTimeout  time.Duration
    WorkerCount  int
    QueueSize    int
    DrainTimeout time.Duration
}

type Server struct {
    cfg     ServerConfig
    mux     *http.ServeMux
    metrics *AlertMetrics
}

func NewServer(cfg ServerConfig, metrics *AlertMetrics) *Server

// RegisterWebhook registers the POST /webhook handler with enqueue logic.
// process is called by workers for each dequeued alert.
func (s *Server) RegisterWebhook(handler http.HandlerFunc)

// Run starts the worker pool, HTTP server, and blocks until shutdown is complete.
func (s *Server) Run(process func(ctx context.Context, alert AlertPayload))
```

Encapsulates: worker pool, buffered channel, WaitGroup, signal handling, graceful shutdown, `/health`, `/metrics` registration.

#### 1b. Pipeline extraction

Move `processAlert` into the respective `internal/` packages as an exported function:

```go
// internal/k8s/pipeline.go
func ProcessAlert(ctx context.Context, deps K8sDeps, alert shared.AlertPayload)

type K8sDeps struct {
    Gatherer    ContextGatherer
    Analyzer    shared.Analyzer
    Publishers  []shared.Publisher
    Cooldown    *shared.CooldownManager
    Metrics     *shared.AlertMetrics
    SystemPrompt string
}
```

```go
// internal/checkmk/pipeline.go
func ProcessAlert(ctx context.Context, deps CheckMKDeps, alert shared.AlertPayload)

type CheckMKDeps struct {
    Gatherer     ContextGatherer
    Analyzer     shared.Analyzer
    SSHDialer    *SSHDialer
    Publishers   []shared.Publisher
    Cooldown     *shared.CooldownManager
    Metrics      *shared.AlertMetrics
    Config       Config
}
```

#### 1c. Resulting `main.go` (~30-40 lines each)

Each `main.go` reduces to: load config, construct dependencies, build mux with webhook handler, call `shared.Server.Run()`.

#### 1d. Config helpers in shared

```go
// internal/shared/config.go
func EnvOrDefault(key, fallback string) string
func ParseIntEnv(key, fallback string, min, max int) int  // exits on invalid
func RequireEnv(key string) string                        // exits if empty
func BuildNtfyPublishers() []Publisher
```

## 2. Dependency Injection: HTTP Clients as Struct Fields (P2)

### Problem

Four `*http.Client` instances as package-level variables:
- `claudeHTTPClient` (`shared/claude.go:21`)
- `ntfyHTTPClient` (`shared/ntfy.go:13`)
- `promHTTPClient` (`k8s/context.go:20`)
- `checkmkHTTPClient` (`checkmk/context.go:17`)

Tests swap globals and restore them — fragile, not parallel-safe.

### Design

#### 2a. Claude client as struct

```go
// shared/claude.go
type ClaudeClient struct {
    HTTP    *http.Client
    BaseURL string
    APIKey  string
    Model   string
}

func NewClaudeClient(cfg BaseConfig) *ClaudeClient

func (c *ClaudeClient) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error)
func (c *ClaudeClient) RunToolLoop(ctx context.Context, systemPrompt, userPrompt string,
    tools []Tool, maxRounds int, handleTool ToolHandler) (string, error)
```

Implements `shared.Analyzer` interface (see section 7).

#### 2b. NtfyPublisher with injected client

```go
type NtfyPublisher struct {
    HTTP        *http.Client
    URL         string
    Topic       string
    Token       string
    RetryDelays []time.Duration  // no more mutable global
}
```

#### 2c. Prometheus client as struct

```go
// k8s/prometheus.go
type PrometheusClient struct {
    HTTP *http.Client
    URL  string
}

func (p *PrometheusClient) Query(ctx context.Context, query string) string
```

#### 2d. CheckMK API client as struct

```go
// checkmk/api_client.go
type APIClient struct {
    HTTP     *http.Client
    BaseURL  string
    User     string
    Secret   string
}

func (c *APIClient) GetHostServices(ctx context.Context, hostname string) ([]ServiceInfo, error)
func (c *APIClient) ValidateAndDescribeHost(ctx context.Context, hostname, hostAddress string) (*HostInfo, error)
```

## 3. CI/CD: Tests, Linting, Vulnerability Scanning (P0/P2)

### Problem

CI pipeline only builds Docker images. 188 tests never run in CI.

### Design

#### 3a. Test job (P0)

```yaml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - uses: actions/setup-go@v5
      with:
        go-version-file: go.mod
    - run: go vet ./...
    - run: go test -race -count=1 ./...
```

#### 3b. Lint job (P2)

```yaml
lint:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - uses: actions/setup-go@v5
      with:
        go-version-file: go.mod
    - uses: golangci/golangci-lint-action@v7
```

#### 3c. Dependency gate

```yaml
build-k8s:
  needs: [test, lint]
build-checkmk:
  needs: [test, lint]
```

#### 3d. Vulnerability scanning (P2)

- `govulncheck` in the test job
- Trivy as post-build step on Docker images

## 4. Security Hardening (P1/P2)

### 4a. Bound Prometheus response body (P1)

`k8s/context.go:45` — the only HTTP client without `io.LimitReader`:

```go
// Before:
body, err := io.ReadAll(resp.Body)

// After:
body, err := io.ReadAll(io.LimitReader(resp.Body, shared.MaxResponseBytes))
```

### 4b. Config validation at startup (P2)

Replace silent `strconv.Atoi` fallback-to-zero with `shared.ParseIntEnv` that validates range and exits on invalid input:

- `COOLDOWN_SECONDS`: min=0, max=86400
- `MAX_LOG_BYTES`: min=256, max=1048576
- `MAX_AGENT_ROUNDS`: min=1, max=50
- `PORT`: min=1, max=65535

### 4c. SSH denylist footgun warning (P2)

Log a prominent warning when `SSH_DENIED_COMMANDS` is set but empty:

```go
if len(sshDeniedCommands) == 0 && ok {
    slog.Warn("SSH_DENIED_COMMANDS is empty — all commands are allowed, no denylist active")
}
```

### 4d. Generic JSON error messages (Info)

Replace `fmt.Sprintf("invalid JSON: %v", err)` with a generic message in both webhook handlers. Low priority for internal-VPN endpoints.

## 5. Observability (P3)

### 5a. Histogram metrics

Add to `AlertMetrics`:
- `alert_analyzer_processing_duration_seconds` — end-to-end from dequeue to publish
- `alert_analyzer_claude_api_duration_seconds` — Claude API call latency
- `alert_analyzer_ssh_command_duration_seconds` — SSH command execution time (checkmk only)

Manual Prometheus text format with `_bucket`, `_sum`, `_count` suffixes. No external library needed.

### 5b. Readiness probe

```
GET /health  → always 200 (liveness probe, keep as-is)
GET /ready   → 200 if downstream dependencies reachable, 503 otherwise
```

k8s-analyzer checks: Prometheus URL, K8s API.
checkmk-analyzer checks: CheckMK API URL.

Short timeouts (2s) on dependency pings. Suitable for Kubernetes `readinessProbe`.

### 5c. Configurable log level and JSON output

```go
LOG_LEVEL env var: "debug", "info" (default), "warn", "error"
LOG_FORMAT env var: "text" (default), "json"
```

JSON logging is better for log aggregation (Loki, etc.).

## 6. Concurrency and Performance (P2/P3)

### 6a. Parallelize K8s context gathering (P2)

Within `GetKubeContext`, Events, Pods, and Logs queries are independent. Use `errgroup.Group` or parallel goroutines+channels to reduce latency from sum-of-three to max-of-three.

### 6b. Cache parsed SSH key signer (P3)

```go
type SSHDialer struct {
    signer          ssh.Signer
    hostKeyCallback ssh.HostKeyCallback
    user            string
    timeout         time.Duration
}

func NewSSHDialer(cfg Config) (*SSHDialer, error)  // parse key+known_hosts once
func (d *SSHDialer) Dial(hostAddress string) (*ssh.Client, error)
```

Constructed once at startup, injected into `CheckMKDeps`.

### 6c. Cooldown eviction (Info)

Current O(n) scan on every `CheckAndSet` is fine for home-cluster scale. If alert volume grows significantly, consider a background goroutine with periodic cleanup. No action needed now.

## 7. Interface Design (P2)

### 7a. Analyzer interface

```go
// shared/interfaces.go
type Analyzer interface {
    Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}
```

`ClaudeClient` implements this. Tests inject a mock.

### 7b. ContextGatherer interface

```go
// shared/interfaces.go
type ContextGatherer interface {
    GatherContext(ctx context.Context, alert AlertPayload) AnalysisContext
}
```

`k8s.ContextGatherer` and `checkmk.ContextGatherer` structs implement this.

### 7c. Unify ClaudeResponse and ToolResponse

Eliminate `ClaudeResponse` — use `ToolResponse` for both single-turn and tool-use calls. `AnalyzeWithClaude` ignores tool-specific fields. Reduces type duplication.

### 7d. FormatForPrompt test

Add a unit test for `AnalysisContext.FormatForPrompt()` — it assembles every Claude prompt.

## 8. Dockerfile and Operational Details (P3)

### 8a. Add `.dockerignore`

```
.git
.github
docs
*.md
```

### 8b. Pin Alpine digest (optional)

```dockerfile
FROM alpine:3.21@sha256:<digest>
```

For build reproducibility. Low priority for home-cluster use.

## Implementation Order

Recommended sequence respecting dependencies:

1. **P0: CI tests** — Immediate safety net, no code changes needed
2. **P1: Prometheus LimitReader** — One-line fix
3. **P1/P2: Architecture refactor** — Server scaffold, pipeline extraction, DI, interfaces (sections 1, 2, 7 together as one coherent refactor)
4. **P2: Config validation** — Builds on shared config helpers from step 3
5. **P2: CI lint + vuln scanning** — Extends CI from step 1
6. **P2: K8s context parallelization** — Independent of other changes
7. **P3: Observability** — Histograms, readiness probe, log config
8. **P3: SSH key caching, .dockerignore, minor items**

# Anthropic SDK Migration — Design

**Date**: 2026-05-02
**Status**: Approved (pending implementation plan)
**Scope**: `internal/shared/` HTTP client, plus call-site updates in `internal/k8s/agent.go`, `internal/checkmk/agent.go`, both test suites, and `cmd/*/main.go`
**Issue**: [#8 — Migrate Claude HTTP client to anthropic-sdk-go](https://github.com/madic-creates/claude-alert-analyzer/issues/8)

## Problem

The analyzer ships a ~440-line hand-rolled HTTP client for the Claude Messages API (`internal/shared/claude.go`). Phase 1 (PR #7) added significant `cache_control` plumbing, an extended `Usage` struct with cache-token fields, and retry logic with fixed 2s/4s backoff delays. All of that is provided by the official [`anthropic-sdk-go`](https://github.com/anthropics/anthropic-sdk-go) as typed struct fields and configurable options out of the box.

This causes three problems:

1. **The Phase 1 breaking change is not fully healed**: The URL-conditional `Authorization: Bearer` auth was removed in Phase 1. The clean way to bring it back is the SDK, which natively honors `ANTHROPIC_AUTH_TOKEN`. As long as the hand-rolled client lives, OpenRouter remains unusable without an auth-translating proxy.
2. **Maintenance burden**: Every new Anthropic beta header, every additional cache-mode variant, every new tool format has to be added by hand instead of arriving automatically via Renovate-driven SDK bumps.
3. **Duplicated code**: Retry, JSON marshal/unmarshal, header setting, response parsing — all of it is already implemented and tested in the SDK.

## Goals

- Replace the hand-rolled HTTP client with `anthropic-sdk-go`
- Keep `internal/k8s/pipeline.go` and `internal/checkmk/pipeline.go` source-unchanged. `Analyzer` in `internal/shared/interfaces.go` is bit-identical (no tool-type reference). `ToolLoopRunner` changes its `tools` parameter element type from `shared.Tool` to `anthropic.ToolUnionParam` — call-sites in `agent.go` and pipeline test mocks adopt the new type, but pipeline orchestration code is not touched.
- Restore OpenRouter compatibility via `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL`
- Preserve Phase 1 behavior at the public-API level: 3 cache breakpoints in the wire body, atomic per-analysis token recording, 2 MiB body cap before bytes reach the SDK, latency histogram observed once per round-trip after full body consumption, forced summary with `tool_choice: none`, retry on 429/5xx
- Reduce code volume in `internal/shared/claude.go` from ~440 to ~150 lines

### Acknowledged behavior differences (acceptable, not bit-for-bit)

- **Retry codes**: SDK retries `408`, `409`, `429`, `5xx`, plus connection errors. Today: `429` + `5xx` only. The expanded set is semantically correct.
- **Backoff curve**: SDK uses exponential backoff with jitter; today's code uses fixed `2s/4s`. Worst-case wait stays under the 120 s HTTP timeout.
- **200-OK with embedded `error` body**: The current code parses the JSON body, sees `result.Error != nil`, and returns an explicit error. The SDK treats `200 OK` as success, parses content, and ignores any embedded `error` field. After migration, such a response yields an empty analysis (existing pipeline-level empty-analysis handling applies — see Error Handling section). The Anthropic API does not emit this shape in normal operation; the current tests defend against a hypothetical server bug. We drop those tests as obsolete (rationale in the test-migration section).

## Non-Goals

- **Phase 2 components**: Circuit breaker, storm detector, group cooldown — all remain unimplemented. The migration PR builds **no** hook for them. Phase 2 is a separate PR.
- **SDK-swap flexibility**: No type aliases, no translation layer. `anthropic-sdk-go` is the single source of truth for tool, message, and cache types. Non-Anthropic LLMs are explicitly out of scope.
- **Per-round token recording**: Today `RecordClaudeUsage` is called once per analysis (sum across all rounds). That stays.
- **Streaming responses**: Today's code is sync, the SDK PR stays sync. Streaming is a future, separate decision.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ cmd/k8s-analyzer · cmd/checkmk-analyzer (main.go)              │
│   - reads ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN              │
│   - reads ANTHROPIC_BASE_URL (optional)                         │
│   - validates: exactly one auth var must be set                 │
│   - unsets the three env vars after reading (hermetic SDK)      │
│   - builds shared.BaseConfig                                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│ internal/shared/claude.go                                       │
│   ClaudeClient { sdk *anthropic.Client, Model, metrics, source }│
│     Analyze(ctx, model, system, user) → string                  │
│     RunToolLoop(ctx, model, system, user, tools, max, handler)  │
│       → string, rounds, exhausted, error                        │
│   Cache control on system block + last tool + last tool_result  │
└────────────────────────────┬────────────────────────────────────┘
                             │ via anthropic.Client
                             │      option.WithHTTPClient(...)
┌────────────────────────────▼────────────────────────────────────┐
│ internal/shared/transport.go                                    │
│   LimitedTransport { inner, maxBytes, durationHistogram }       │
│     RoundTrip:                                                  │
│       1. start = now                                            │
│       2. inner.RoundTrip                                        │
│       3. on error: histogram.Observe(elapsed); return           │
│       4. on success: wrap resp.Body with                        │
│          timedLimitedReadCloser:                                │
│            - LimitReader(MaxResponseBytes)                      │
│            - Close() observes histogram once                    │
└─────────────────────────────────────────────────────────────────┘
```

### Data flow change

**Today** (`sendRequest`):
```
Build ToolRequest struct → json.Marshal → http.NewRequest → set headers
→ HTTP.Do → ReadAll(LimitReader) → json.Unmarshal → ToolResponse → return
```

**New**:
```
Build anthropic.MessageNewParams → sdk.Messages.New(ctx, params)
→ *anthropic.Message returned (SDK does marshal/headers/retry/unmarshal)
```

Body cap and latency histogram live in the transport layer **below**, transparent to the SDK. Latency is observed when the body is closed by the SDK (Phase 1 semantics: post-body-read), not eagerly on `RoundTrip` return.

## Components

### `internal/shared/types.go` — Deleted

The following hand-rolled types are removed entirely:

- `CacheControl`, `SystemBlock`, `Tool`, `InputSchema`, `Property`, `Items`
- `ContentBlock`, `ToolMessage`, `ToolChoice`
- `ToolRequest`, `ToolResponse`

The non-tool types defined in this file move to a new `internal/shared/payload.go`:

- `AnalysisContext`, `ContextSection`, `Publisher`, `AlertPayload`, `BaseConfig`

`BaseConfig` gains two separate auth fields in the process (see env-var section).

### `internal/shared/interfaces.go` — Signature change

```go
type ToolLoopRunner interface {
    RunToolLoop(
        ctx context.Context,
        model, systemPrompt, userPrompt string,
        tools []anthropic.ToolUnionParam,  // was []shared.Tool
        maxRounds int,
        handleTool func(name string, input json.RawMessage) (string, error),
    ) (analysis string, rounds int, exhausted bool, err error)
}
```

`Analyzer` is unchanged (no tool-type reference). The element type for `tools` is `anthropic.ToolUnionParam` (the SDK's discriminated-union wrapper) because that is what `MessageNewParams.Tools` requires. Call-sites in `internal/k8s/agent.go`, `internal/checkmk/agent.go`, and the four pipeline/agent test files adopt the new type. `internal/k8s/pipeline.go` and `internal/checkmk/pipeline.go` do not call `RunToolLoop` directly and are not touched.

### `internal/shared/claude.go` — Rewritten

```go
type ClaudeClient struct {
    sdk    *anthropic.Client
    Model  string

    // Pipeline bridge to AlertMetrics; nil for tests that do not assert metrics.
    metrics *AlertMetrics
    source  string
}

func NewClaudeClient(cfg BaseConfig, transport http.RoundTripper) *ClaudeClient {
    httpClient := &http.Client{Timeout: 120 * time.Second, Transport: transport}

    opts := []option.RequestOption{
        option.WithHTTPClient(httpClient),
        option.WithMaxRetries(2),
    }
    // Always pass both options, possibly with empty strings, so the SDK
    // never falls back to its own ANTHROPIC_*_KEY/TOKEN env-var lookups.
    // main.go has already validated exactly one of these is non-empty.
    opts = append(opts, option.WithAPIKey(cfg.APIKey))
    opts = append(opts, option.WithAuthToken(cfg.AuthToken))
    if cfg.APIBaseURL != "" {
        opts = append(opts, option.WithBaseURL(cfg.APIBaseURL))
    }
    sdk := anthropic.NewClient(opts...)
    return &ClaudeClient{sdk: &sdk, Model: cfg.ClaudeModel}
}

func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics, source string) *ClaudeClient {
    c.metrics = m
    c.source = source
    return c
}
```

Constructor change: `NewClaudeClient` now takes an `http.RoundTripper`. `cmd/*/main.go` builds `LimitedTransport` and passes it in. This enables (a) latency-histogram binding in the transport, and (b) tests without a real transport.

`WithPrometheusMetrics` now sets only the metrics pointers used by `RecordClaudeUsage`. The histogram binding moves into the transport constructor (see below) because it operates per round-trip, not per logical request.

#### `Analyze`

```go
func (c *ClaudeClient) Analyze(ctx context.Context, model, systemPrompt, userPrompt string) (string, error) {
    if model == "" {
        model = c.Model
    }
    msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
        Model:     anthropic.Model(model),
        MaxTokens: 2048,
        System: []anthropic.TextBlockParam{{
            Text:         systemPrompt,
            CacheControl: anthropic.NewCacheControlEphemeralParam(),
        }},
        Messages: []anthropic.MessageParam{
            anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
        },
    })
    if err != nil { return "", err }

    c.metrics.RecordClaudeUsage(c.source, "all", model,
        int(msg.Usage.InputTokens), int(msg.Usage.OutputTokens),
        int(msg.Usage.CacheCreationInputTokens), int(msg.Usage.CacheReadInputTokens))

    if msg.StopReason != "" && msg.StopReason != anthropic.StopReasonEndTurn {
        slog.Warn("analysis response may be truncated",
            "stop_reason", msg.StopReason,
            "model", model,
            "outputTokens", msg.Usage.OutputTokens)
    }

    return extractText(msg.Content), nil
}
```

Behavior preserved 1:1: cache control on the system block, `MaxTokens: 2048`, the `RecordClaudeUsage` call, the truncation warning on non-`end_turn` stop reasons, an empty result string when no text blocks are returned. SDK errors carry the original API error type and message via `*anthropic.Error` (see Error Handling for assertion patterns).

#### `RunToolLoop`

Structurally unchanged from today: `for round := range maxRounds`, then forced summary. Per iteration, the key changes:

```go
params := anthropic.MessageNewParams{
    Model:     anthropic.Model(model),
    MaxTokens: 4096,
    System:    []anthropic.TextBlockParam{{Text: systemPrompt, CacheControl: anthropic.NewCacheControlEphemeralParam()}},
    Tools:     toolsWithCachedTail(tools),
    Messages:  messages,
}
msg, err := c.sdk.Messages.New(ctx, params)
```

Where `tools []anthropic.ToolUnionParam` (the parameter to `RunToolLoop`, matching the SDK's `MessageNewParams.Tools` field type), and `toolsWithCachedTail` is a small helper that copies the slice and attaches `CacheControl: anthropic.NewCacheControlEphemeralParam()` to the `OfTool` variant of the last element (Phase 1's `withCachedTail` behavior).

`messages []anthropic.MessageParam` — on follow-up rounds, the last `tool_result` block of the most-recently-appended user message receives `CacheControl: anthropic.NewCacheControlEphemeralParam()` (breakpoint #3, Phase 1 behavior).

Tool-use iteration:
```go
for _, block := range msg.Content {
    switch v := block.AsAny().(type) {
    case anthropic.ToolUseBlock:
        output, err := handleTool(v.Name, v.Input)
        // … as today, plus appending tool_result to the user message
    case anthropic.TextBlock:
        // consumed by extractText on end_turn
    }
}
```

Forced summary after `maxRounds` is exhausted:

```go
// Append summary text block to the last user message (which already contains tool_result blocks)
// — Phase 1's fix avoids the "roles must alternate" 400 by appending instead of starting a new turn.
appendTextToLastUserMessage(&messages, summaryPrompt)

summaryParams := anthropic.MessageNewParams{
    Model:      anthropic.Model(model),
    MaxTokens:  4096,
    System:     ...,
    Tools:      toolsWithCachedTail(tools),
    ToolChoice: anthropic.ToolChoiceUnionParam{
        OfNone: &anthropic.ToolChoiceNoneParam{},
    },
    Messages:   messages,
}
```

The `ToolChoice` field type is `ToolChoiceUnionParam`; the `OfNone` variant carries an empty `ToolChoiceNoneParam` struct. (This replaces today's `ToolChoice: &ToolChoice{Type: "none"}`.)

Token totals are aggregated into local `totalInput`, `totalOutput`, `totalCacheCreation`, `totalCacheRead` and passed to `RecordClaudeUsage` **once at the end** (`end_turn` / no-tool-use fallback / after forced summary) — atomic per logical analysis, exactly as in Phase 1.

`maxRounds <= 0` is rejected **before** the first SDK call and returns an error immediately — `TestRunToolLoop_FallbackWhenNoToolRoundsOccurred` stays green.

### `internal/shared/transport.go` — New

```go
type LimitedTransport struct {
    inner             http.RoundTripper
    maxBytes          int64
    durationHistogram prometheus.Observer  // optional; nil = no observation
}

func NewLimitedTransport(inner http.RoundTripper, hist prometheus.Observer) *LimitedTransport {
    if inner == nil {
        inner = http.DefaultTransport
    }
    return &LimitedTransport{
        inner:             inner,
        maxBytes:          MaxResponseBytes,
        durationHistogram: hist,
    }
}

func (lt *LimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    start := time.Now()
    resp, err := lt.inner.RoundTrip(req)
    if err != nil {
        // Transport error: no response body to read; observe immediately so
        // the failure is still visible in the latency histogram (Phase 1 behavior).
        lt.observe(start)
        return nil, err
    }
    // Wrap the body so we observe latency *after* the SDK has finished
    // reading it. This matches Phase 1's "observe after ReadAll" semantics
    // and keeps the histogram a meaningful end-to-end metric.
    resp.Body = &timedLimitedReadCloser{
        r:       io.LimitReader(resp.Body, lt.maxBytes),
        c:       resp.Body,
        start:   start,
        observe: lt.observe,
    }
    return resp, nil
}

func (lt *LimitedTransport) observe(start time.Time) {
    if lt.durationHistogram != nil {
        lt.durationHistogram.Observe(time.Since(start).Seconds())
    }
}

type timedLimitedReadCloser struct {
    r       io.Reader
    c       io.Closer
    start   time.Time
    observe func(time.Time)
    once    sync.Once
}

func (t *timedLimitedReadCloser) Read(p []byte) (int, error)  { return t.r.Read(p) }
func (t *timedLimitedReadCloser) Close() error {
    t.once.Do(func() { t.observe(t.start) })
    return t.c.Close()
}
```

`MaxResponseBytes = 2 * 1024 * 1024` stays as an exported constant in this file. `sync.Once` guards the observation in case `Close` is called twice.

`cmd/*/main.go` wires the transport:

```go
hist := metrics.Prom.ClaudeAPIDuration.WithLabelValues("k8s") // or "checkmk"
transport := shared.NewLimitedTransport(http.DefaultTransport, hist)
client := shared.NewClaudeClient(cfg, transport).WithPrometheusMetrics(metrics, "k8s")
```

### Env vars and `BaseConfig`

```go
type BaseConfig struct {
    ClaudeModel     string
    CooldownSeconds int
    Port            string
    MetricsPort     string
    WebhookSecret   string

    APIBaseURL string  // ANTHROPIC_BASE_URL — optional; SDK default = https://api.anthropic.com
    APIKey     string  // ANTHROPIC_API_KEY  — optional; sets x-api-key header
    AuthToken  string  // ANTHROPIC_AUTH_TOKEN — optional; sets Authorization: Bearer
}
```

`cmd/k8s-analyzer/main.go` and `cmd/checkmk-analyzer/main.go`:

```go
apiKey := os.Getenv("ANTHROPIC_API_KEY")
authToken := os.Getenv("ANTHROPIC_AUTH_TOKEN")
baseURL := os.Getenv("ANTHROPIC_BASE_URL")

switch {
case apiKey == "" && authToken == "":
    log.Fatal("either ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN must be set")
case apiKey != "" && authToken != "":
    log.Fatal("set exactly one of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN, not both")
}

// Unset the three env vars so the SDK cannot fall back to them later
// in the process lifetime; main.go is the single source of truth.
os.Unsetenv("ANTHROPIC_API_KEY")
os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
os.Unsetenv("ANTHROPIC_BASE_URL")

cfg := shared.BaseConfig{
    APIKey:     apiKey,
    AuthToken:  authToken,
    APIBaseURL: baseURL,
    // … rest
}
```

**Hard cut**: The legacy names `API_KEY` and `API_BASE_URL` are removed from `main.go`. Existing deployments break on restart until manifests are updated. Migration is trivial (rename two env vars), but operator-visible — hence `feat!:` commit.

**Both-auth policy**: Setting both `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` is a startup error. Operators must pick exactly one. This avoids an undocumented SDK precedence becoming load-bearing in production.

**Hermetic SDK**: `main.go` unsets all three env vars after reading them. The SDK constructor receives explicit values via `option.WithAPIKey(cfg.APIKey)`, `option.WithAuthToken(cfg.AuthToken)`, and (when set) `option.WithBaseURL(cfg.APIBaseURL)`. Empty strings are passed when not configured, suppressing the SDK's env-var fallback path.

### Callers in `internal/k8s/agent.go` and `internal/checkmk/agent.go`

Today:
```go
var kubectlTool = shared.Tool{
    Name: "kubectl_exec",
    InputSchema: shared.InputSchema{
        Type: "object",
        Properties: map[string]shared.Property{
            "args": {Type: "array", Description: "...", Items: &shared.Items{Type: "string"}},
        },
        Required: []string{"args"},
    },
}
```

New:
```go
var kubectlTool = anthropic.ToolUnionParam{
    OfTool: &anthropic.ToolParam{
        Name:        "kubectl_exec",
        Description: anthropic.String("..."),
        InputSchema: anthropic.ToolInputSchemaParam{
            Properties: map[string]any{
                "args": map[string]any{
                    "type":        "array",
                    "description": "...",
                    "items":       map[string]any{"type": "string"},
                },
            },
            Required: []string{"args"},
        },
    },
}
```

`promqlTool` and `sshTool` follow the same pattern. The mock clients in the `*_test.go` files take `[]anthropic.ToolUnionParam` in their method signatures.

`toolsWithCachedTail(tools []anthropic.ToolUnionParam) []anthropic.ToolUnionParam` mutates a copied slice's last element to set `tools[len-1].OfTool.CacheControl = anthropic.NewCacheControlEphemeralParam()`. The helper handles the `OfTool` nil-check (skips when the last element is not a `Tool`-variant union).

## Tests

### `claude_test.go` — Migration

Strategy: `httptest.Server` stays, the SDK is pointed at it via `option.WithBaseURL(srv.URL)`. Cache-marker tests continue to inspect the raw JSON body, which is now the SDK-serialised output. Tests that need to disable retries pass `option.WithMaxRetries(0)` (the test wires this through a constructor variant or by accepting `[]option.RequestOption` in a test-only `NewClaudeClientForTest` helper).

#### Tests that stay (only the client constructor changes)

- `TestAnalyze_Success`, `TestAnalyze_MultipleTextBlocks`, `TestAnalyze_EmptyContent`, `TestAnalyze_NonTextBlocksIgnored`
- `TestAnalyze_MaxTokensStopReason` — `max_tokens` stop reason continues to be passed through
- `TestAnalyze_ContextCancellation`
- `TestAnalyze_UsesProvidedModel`, `TestAnalyze_SystemPromptHasCacheControl`
- `TestRunToolLoop_EndTurnImmediately`, `TestRunToolLoop_OneToolRoundThenEnd`, `TestRunToolLoop_MaxRoundsForcesSummary`
- `TestRunToolLoop_APIError`, `TestRunToolLoop_ToolHandlerError`
- `TestRunToolLoop_MultipleToolsInOneRound`, `TestRunToolLoop_MaxTokensStopReason`
- `TestRunToolLoop_MaxRounds_NoConsecutiveUserMessages` — critical behavioral test
- `TestRunToolLoop_SummaryRequestFails`, `TestRunToolLoop_SummaryRequestHasToolChoiceNone`
- `TestRunToolLoop_FallbackWhenNoToolRoundsOccurred` (maxRounds=0 → error)
- `TestRunToolLoop_LastToolHasCacheControl`, `TestRunToolLoop_LastToolResultHasCacheControl`, `TestRunToolLoop_UsesProvidedModel`

#### Tests rewritten because the SDK uses typed errors

The SDK returns `*anthropic.Error` for non-2xx responses. That type carries `StatusCode`, `Request`, `Response`, `RequestID`, and `RawJSON()` — but **no** `Type` or `Message` fields. To assert structured error content, tests unmarshal `apiErr.RawJSON()` into a local error-shaped struct or use `apiErr.Response.Body`.

- `TestAnalyze_HTTPError` — server returns `429`. With `option.WithMaxRetries(0)` the SDK fails fast. Assert `errors.As(err, &apiErr *anthropic.Error)` and `apiErr.StatusCode == http.StatusTooManyRequests`. (Phase-1 equivalent: `TestAnalyze_HTTPError` at `claude_test.go:185`.)
- `TestAnalyze_ParseResponseError` — server returns `Content-Type: text/html` with `200 OK` and an HTML body. Assert `err != nil`. The SDK error is not a typed `*anthropic.Error` here (status was 200) — use a substring assertion against the error message; the test treats any non-nil error as the contract. The exact substring is captured by the implementation as the canonical SDK error string.
- `TestRunToolLoop_SummaryParseFailure` — same approach as `TestAnalyze_ParseResponseError` for the forced-summary call. Assert that the returned error wraps the original with the `summary` prefix preserved by `RunToolLoop`.

#### Tests dropped as obsolete

The hand-rolled client treated a `200 OK` response with an embedded `error` field as a hard error (`if result.Error != nil`). The SDK does not — it parses the `Message` and ignores the `error` field. The Anthropic API does not actually emit this shape; the current tests defend against a hypothetical server bug. Acceptance: such a malformed response now yields an empty analysis, which is handled by the existing pipeline-level empty-result guard at `internal/k8s/pipeline.go:94-104` and `internal/checkmk/pipeline.go:112-122`. Both branches log `"analysis returned empty result, treating as failure"`, publish an `"Analysis produced empty result"` ntfy notification, and increment `AlertsFailed` — exactly the failure path Phase 1 produced when the embedded error was caught explicitly. No change is needed in `Analyze` or `RunToolLoop`.

- `TestAnalyze_APIErrorInBody` (`claude_test.go:136`) — dropped
- `TestRunToolLoop_APIErrorInBody` (`claude_test.go:404`) — dropped
- `TestRunToolLoop_SummaryAPIErrorInBody` (`claude_test.go:781`) — dropped
- `TestSendRequest_MarshalFailure` (`claude_test.go:1001`) — dropped; SDK inputs are typed and non-marshalable inputs are no longer reachable

#### Tests moved to `claude_test.go` from old `sendRequest`-named tests

Today's `TestSendRequest_*` tests target the unexported `sendRequest`, which no longer exists. They are renamed and relocated:

- `TestSendRequest_RetriesOnTransientError` → `TestClaudeClient_RetriesOnTransientError` in `claude_test.go`. Inner test `httptest.Server` returns `503` twice then `200`; client built with default `option.WithMaxRetries(2)`; assert that `Analyze` succeeds and `httptest.Server` was hit 3 times. **Retries happen inside the SDK; this test validates the SDK's retry behavior end-to-end via our wiring**, not `LimitedTransport`'s.
- `TestSendRequest_NoRetryOnClientError` → `TestClaudeClient_NoRetryOnClientError` in `claude_test.go`. Server returns `400`; assert `Analyze` fails after exactly 1 hit (with default retries). Useful regression guard for SDK retry-policy changes.

#### Tests that move to `transport_test.go`

These tests target only `LimitedTransport` — no SDK involved.

- `TestSendRequest_OversizedResponseIsBounded` → `TestLimitedTransport_OversizedBodyCapped`
- `TestSendRequest_DurationHistogramObservedOnSuccess` → `TestLimitedTransport_HistogramObservedOnSuccess`
- `TestSendRequest_DurationHistogramObservedOnNonOK` → `TestLimitedTransport_HistogramObservedOnNonOK`

#### Tests replaced by new auth-header tests

`TestSendRequest_AlwaysUsesXAPIKey` (`claude_test.go:206`) is replaced by three tests that validate the new auth contract end-to-end:

- `TestNewClaudeClient_APIKeyHeader` — `cfg.APIKey="tok"`, `cfg.AuthToken=""`: outgoing request carries `x-api-key: tok`, no `Authorization` header
- `TestNewClaudeClient_AuthTokenHeader` — `cfg.APIKey=""`, `cfg.AuthToken="bearer-tok"`: outgoing request carries `Authorization: Bearer bearer-tok`, no `x-api-key`. **This is the acceptance gate for OpenRouter compatibility.**
- `TestNewClaudeClient_AnthropicVersionHeader` — replaces the `anthropic-version` assertion that was bundled into `TestSendRequest_AlwaysUsesXAPIKey`. The SDK is responsible for setting this header; the test asserts the outgoing value is non-empty and matches the SDK-declared version (read from a constant exported by the SDK if available, otherwise asserted via substring).

The both-auth-set case is **not** a test of SDK behavior — it is rejected at startup (`main.go`) and never reaches the client. A `main_test.go` (or `cmd/k8s-analyzer/main_test.go`-style integration) test verifies that startup fails when both env vars are present; see Acceptance Criteria.

### `transport_test.go` — New

Pure unit tests against `LimitedTransport` using a mock `http.RoundTripper` as inner transport. No SDK, no `httptest.Server`.

```go
func TestLimitedTransport_OversizedBodyCapped(t *testing.T) { ... }
func TestLimitedTransport_HistogramObservedOnSuccess(t *testing.T) { ... }
func TestLimitedTransport_HistogramObservedOnNonOK(t *testing.T) { ... }
func TestLimitedTransport_HistogramObservedOnTransportError(t *testing.T) { ... }
func TestLimitedTransport_HistogramObservedAfterBodyClose(t *testing.T) { ... }
```

The last test verifies the Phase-1-preserving semantic: histogram is observed when `Body.Close()` is called (the SDK does this after parsing), not eagerly on `RoundTrip` return.

### Pipeline tests

`internal/k8s/pipeline_test.go`, `internal/checkmk/pipeline_test.go`, `internal/k8s/agent_test.go`, `internal/checkmk/agent_test.go`: mock implementations of `Analyzer` and `ToolLoopRunner` get `[]anthropic.ToolUnionParam` in the `RunToolLoop` signature. Logic in the mocks stays identical — they test pipeline behavior, not SDK details.

## Error Handling

- **Anthropic API errors (429/5xx)**: SDK retries 2× with exponential backoff (`option.WithMaxRetries(2)`). On final failure, returns `*anthropic.Error`. Tests use `errors.As(err, &apiErr)` and assert `apiErr.StatusCode`. Structured error fields (e.g., `error.type`) require `apiErr.RawJSON()` parsing or substring matching against the error message.
- **408/409 and connection errors**: SDK retries these as well. Not retried today; semantically correct. Recorded as a known behavior change in Goals.
- **Body cap exceeded**: `LimitedTransport` caps the body at 2 MiB before the SDK reads it. SDK observes a truncated body and returns a parse error. `TestLimitedTransport_OversizedBodyCapped` verifies the cap.
- **`maxRounds <= 0`**: Caught in `RunToolLoop` before the first SDK call with an error. Unchanged.
- **Forced summary failure**: SDK error is wrapped with the `summary` prefix in `RunToolLoop`. `TestRunToolLoop_SummaryRequestFails` and `TestRunToolLoop_SummaryParseFailure` verify this.
- **200-OK with embedded `error` body**: SDK returns success with empty content. `extractText` returns `""`. The pipeline already treats empty analyses as failure (slog.Warn + ntfy "empty analysis" notification). This is a known behavior difference from Phase 1; see Goals.
- **Auth at startup**: Both env vars set → `log.Fatal`. Neither set → `log.Fatal`. Exactly one set → proceeds. Verified by acceptance test (see below).
- **Marshal errors**: Cannot occur — SDK inputs are typed.

## Configuration Reference

```
# Anthropic API — new
ANTHROPIC_API_KEY      (optional; sets x-api-key)
ANTHROPIC_AUTH_TOKEN   (optional; sets Authorization: Bearer; required for OpenRouter)
ANTHROPIC_BASE_URL     (optional; default https://api.anthropic.com)
                       # exactly one of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN must be set
                       # both set → startup error
                       # neither set → startup error

# Removed — breaking change
API_KEY                # replaced by ANTHROPIC_API_KEY
API_BASE_URL           # replaced by ANTHROPIC_BASE_URL
```

All other env vars (`PORT`, `METRICS_PORT`, `CLAUDE_MODEL`, `MAX_AGENT_ROUNDS`, `CLAUDE_MODEL_*`, `MAX_AGENT_ROUNDS_*`, `COOLDOWN_SECONDS`, `LOG_LEVEL`, etc.) stay unchanged.

## Acceptance Criteria

### Build & test gates

- [ ] `go test ./... -race` passes (Phase 1 baseline minus the four dropped tests; current count 1037 → expected ≥ 1033 + new tests added by this migration)
- [ ] `CGO_ENABLED=0 go build ./cmd/k8s-analyzer/ && CGO_ENABLED=0 go build ./cmd/checkmk-analyzer/` succeeds
- [ ] `go.mod` lists `github.com/anthropics/anthropic-sdk-go` as a direct dependency

### Behavior preservation

- [ ] Cache-breakpoint tests green: system block, last tool, and last `tool_result` of every follow-up round visible in JSON request bodies (`TestAnalyze_SystemPromptHasCacheControl`, `TestRunToolLoop_LastToolHasCacheControl`, `TestRunToolLoop_LastToolResultHasCacheControl`)
- [ ] Token-recording tests green: `RecordClaudeUsage` called **once per analysis** with correct sums including `cache_creation_input_tokens` and `cache_read_input_tokens`
- [ ] Body-cap test green: `TestLimitedTransport_OversizedBodyCapped` verifies responses larger than 2 MiB are truncated before reaching the SDK
- [ ] Latency-semantics test green: `TestLimitedTransport_HistogramObservedAfterBodyClose` verifies the histogram observation fires on `Close()`, not on `RoundTrip` return
- [ ] Forced-summary `tool_choice: none` gate green: `TestRunToolLoop_SummaryRequestHasToolChoiceNone` verifies the JSON wire body of the summary call contains `"tool_choice":{"type":"none"}` (mapped from `anthropic.ToolChoiceUnionParam{OfNone: ...}`)
- [ ] Auth-header tests: `TestNewClaudeClient_APIKeyHeader` (x-api-key), `TestNewClaudeClient_AuthTokenHeader` (Bearer), `TestNewClaudeClient_AnthropicVersionHeader` all green
- [ ] Retry tests green: `TestClaudeClient_RetriesOnTransientError` verifies SDK retries 503 twice then succeeds; `TestClaudeClient_NoRetryOnClientError` verifies 400 is not retried
- [ ] Empty-analysis pipeline failure path covered: an integration test (k8s pipeline + checkmk pipeline) drives an `Analyzer` mock that returns `("", nil)` and asserts (a) `slog` "analysis returned empty result", (b) ntfy publish with priority "5" titled `Analysis FAILED: ...`, (c) `Cooldown.Clear` called for the fingerprint, (d) `AlertsFailed` counter incremented. This gates the `200 OK + embedded error` behavior change from Phase 1

### Public-API contract

- [ ] `internal/k8s/pipeline.go` and `internal/checkmk/pipeline.go` are untouched (verified by `git diff --stat` showing 0 changes in those files)
- [ ] `Analyzer` interface in `internal/shared/interfaces.go` has identical signature to today
- [ ] `ToolLoopRunner` interface in `internal/shared/interfaces.go` differs only in the `tools` parameter type (`[]anthropic.ToolUnionParam` instead of `[]shared.Tool`)
- [ ] `internal/k8s/agent.go` and `internal/checkmk/agent.go` declare their tools as `anthropic.ToolUnionParam`

### Code-volume goal

- [ ] `wc -l internal/shared/claude.go` reports between 100 and 200 lines (target ~150; today ~440)
- [ ] `grep -r 'shared\.Tool\b\|shared\.ContentBlock\|shared\.ToolMessage\|shared\.SystemBlock\|shared\.CacheControl\|shared\.ToolRequest\|shared\.ToolResponse' internal/ cmd/` returns 0 matches (no translation-layer leftovers)

### Phase-2 isolation

Phase 1 already reserved hook points in `internal/shared/policy.go` (`IsDegraded`, `GroupCooldownTTL` field). The migration PR must not extend those hooks into the client or transport layers. Both greps are scoped to the files this PR is allowed to touch:

- [ ] `grep -nE 'CircuitBreaker|StormDetector|GroupCooldown|ErrCircuitOpen|IsHalfOpenProbe|IsDegraded' internal/shared/claude.go internal/shared/transport.go internal/shared/payload.go cmd/k8s-analyzer/main.go cmd/checkmk-analyzer/main.go` returns 0 matches (no Phase-2 hooks added in the migrated files)
- [ ] `grep -nE 'NewStreaming|MessagesStreaming|StreamingMessage|MessageStream\b' internal/shared/claude.go internal/shared/transport.go` returns 0 matches (no SDK streaming entry points wired in). The pattern targets the exact SDK streaming names; substrings like `upstream` are explicitly excluded

### Operationally-verified, not unit-gated

The following acknowledged behavior changes are observable only against the live Anthropic API and are verified at the Rollout stage rather than by unit tests:

- **Backoff curve** (fixed 2s/4s → exponential with jitter): observed during the 24–48 h staging soak via `claude_api_duration_seconds` p99 — no regression versus pre-merge baseline. Concrete check listed in the Rollout section.
- **408 / 409 retries** (newly retried by the SDK): not synthesizable in staging without a custom proxy; covered by the upstream `anthropic-sdk-go` test suite. The migration trusts that suite. Failure mode is benign: if the SDK regresses on these codes, our existing `claude_api_errors_total` counter increases but no other behavior changes (no infinite-loop or amplifier risk because `option.WithMaxRetries(2)` caps the retry count).
- **Connection-error retries** (newly retried by the SDK): same rationale as 408 / 409 — SDK-default, covered by the SDK's own tests, capped at 2 retries.

These three are listed here explicitly so reviewers do not expect a unit gate for them.

### Auth & startup

- [ ] Startup test verifies `log.Fatal` when both `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are set
- [ ] Startup test verifies `log.Fatal` when neither is set
- [ ] Startup test verifies that `ANTHROPIC_*` env vars are unset after `main.go` initialization (hermetic SDK)

### OpenRouter compatibility

- [ ] OpenRouter smoke test in a staging cluster: deployment with `ANTHROPIC_BASE_URL=https://openrouter.ai/api`, `ANTHROPIC_AUTH_TOKEN=sk-or-v1-...`, send a webhook, confirm a successful analysis is published to ntfy

### Documentation

- [ ] `docs/cost-and-storm-protection.md`: drop the "OpenRouter compatibility deferred" notes; add an "OpenRouter setup" section using `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL`
- [ ] `CLAUDE.md`: drop the breaking-change deferral note about OpenRouter; mention `anthropic-sdk-go` in the architecture description
- [ ] `README.md`: LLM provider section explains the SDK env-var pattern

### Commit hygiene

- [ ] Commit as `feat!:` — operator-visible breaking change due to env-var renames

## Out of Scope

- Phase 2 components (circuit breaker, storm detector, group cooldown) — separate PR per `docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md`
- Streaming responses
- Per-round token recording — counter increments stay atomic per analysis
- An automatic env-var migration helper for operators (e.g. an alias wrapper) — explicitly rejected; the hard cut is the decision
- Defending against `200 OK` responses with embedded `error` fields — the Anthropic API does not emit them in normal operation; the SDK does not surface them; pipeline-level empty-analysis handling is the safety net

## Risks & Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Phase 1 cache markers don't land in the wire body correctly after migration | medium | Wire-body tests stay with `httptest.Server`; the CI gate is explicit |
| SDK type or helper name (e.g. `ToolChoiceUnionParam.OfNone`, `ToolUnionParam.OfTool`) drifts in a future SDK version after the migration ships | low | Cache-marker tests inspect the JSON wire body and would fail if the union shape changes silently; Renovate-driven SDK bumps land in their own PR with this test suite as the gate. SDK names verified at spec-writing time against `pkg.go.dev/github.com/anthropics/anthropic-sdk-go`; current shape is `ToolUnionParam{OfTool: *ToolParam}` and `ToolChoiceUnionParam{OfNone: *ToolChoiceNoneParam}` |
| Backoff behavior changes operationally noticeably | low | Worst case still under the 120 s timeout; SDK default is conservative. If operationally measurable, separate PR with a custom retry option |
| Existing deployments break on update | high (intended) | `feat!:` commit, prominent release notes, trivial migration (rename two env vars) |
| 200-OK-with-embedded-`error` shape regresses silently | low | Non-existent in normal Anthropic API operation; pipeline-level empty-analysis handling catches the edge case if it ever occurs |
| SDK breaking change on later bumps | low–medium | Renovate ships PRs individually; the test suite catches structural problems. Not a blocker for this migration |

## Rollout

1. Merge the PR
2. Staging deploy with `ANTHROPIC_API_KEY=$API_KEY` (rename in the manifests)
3. Observe for 24–48 h:
   - **Cache hit rate** in Grafana (should stay above 50% as before)
   - **Latency**: `claude_api_duration_seconds` p50/p99 versus the pre-merge baseline — neither percentile should regress noticeably; small improvement expected from SDK connection reuse. This is the concrete gate for the backoff-curve change.
   - **Error counters**: `claude_api_errors_total` should not show a step change. A sustained increase isolated to connection / 408 / 409 codes would indicate an SDK retry regression and warrants a follow-up; otherwise these retry classes are accepted as SDK-default and not separately verified.
   - No new error patterns in logs
4. OpenRouter smoke test in a test cluster with `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL`
5. Production deploy

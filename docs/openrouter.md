# Running against OpenRouter

The analyzer always sends `Authorization` via the `x-api-key` header. OpenRouter's Anthropic-compatible endpoint accepts the same request body but expects `Authorization: Bearer`. To keep using OpenRouter, run a small auth-translating proxy in front of it. This document shows three minimal recipes.

If you don't have a strong reason to stay on OpenRouter, skip the proxy and point the analyzer directly at Anthropic — see [Option A](#option-a-go-direct-anthropic-recommended-if-feasible) below.

## Why a proxy is needed

Phase 1 of the cost & storm protection initiative removed the URL-conditional auth branch in `internal/shared/claude.go`. The client now unconditionally sends:

```
x-api-key: <API_KEY>
anthropic-version: 2023-06-01
```

OpenRouter's "Anthropic skin" (`https://openrouter.ai/api/v1/messages`) accepts the same request body and supports prompt caching, tool use, and streaming, but requires:

```
Authorization: Bearer <OPENROUTER_KEY>
```

A header-translating proxy bridges the two. The analyzer talks to the local proxy, the proxy talks to OpenRouter.

Source for OpenRouter's Anthropic-skin behavior: [morphllm.com/openrouter-anthropic-skin](https://www.morphllm.com/openrouter-anthropic-skin).

## Option A: Go direct Anthropic (recommended if feasible)

```
API_BASE_URL=https://api.anthropic.com/v1/messages   # default
API_KEY=sk-ant-...
```

You lose OpenRouter's per-request provider selection (`:nitro`, `:floor`) and the convenience of having one bill across providers. You keep prompt caching at the same Anthropic-direct rates, and you avoid running an extra hop.

## Option B: nginx auth-translating proxy

Minimal `nginx.conf` (only the relevant `server` block):

```nginx
server {
    listen 127.0.0.1:8787;

    location /v1/messages {
        # Read the analyzer's x-api-key, rewrite as Bearer for OpenRouter.
        proxy_set_header Authorization "Bearer $http_x_api_key";
        proxy_set_header x-api-key "";
        proxy_set_header anthropic-version $http_anthropic_version;
        proxy_set_header Content-Type "application/json";

        # OpenRouter's Anthropic skin.
        proxy_pass https://openrouter.ai/api/v1/messages;
        proxy_ssl_server_name on;
        proxy_http_version 1.1;

        # Match the analyzer's HTTP client timeout (120 s for the Anthropic call).
        proxy_read_timeout 130s;
        proxy_send_timeout 130s;

        # Cap response bodies — Phase 1 reads up to 2 MiB.
        client_max_body_size 4m;
    }
}
```

Analyzer config:

```
API_BASE_URL=http://127.0.0.1:8787/v1/messages
API_KEY=sk-or-v1-...   # OpenRouter key, passed through as Bearer by nginx
```

The analyzer sends `x-api-key: sk-or-v1-...`; nginx rewrites it as `Authorization: Bearer sk-or-v1-...` and strips the now-empty `x-api-key`. OpenRouter sees a valid Bearer auth.

## Option C: Caddy proxy

Equivalent setup with Caddy 2 (`Caddyfile`):

```caddy
:8787 {
    handle /v1/messages {
        reverse_proxy https://openrouter.ai {
            header_up Authorization "Bearer {http.request.header.X-Api-Key}"
            header_up -X-Api-Key
            header_up Host openrouter.ai
            transport http {
                tls_server_name openrouter.ai
            }
            rewrite /api/v1/messages
        }
    }
}
```

Same analyzer config as Option B.

## Option D: Tiny Go sidecar

If you prefer code over config (and want to keep the proxy in the same container as the analyzer), a 30-line Go program does the same thing. Compile statically, run alongside the analyzer.

```go
package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	target, _ := url.Parse("https://openrouter.ai/api/v1/messages")
	rp := httputil.NewSingleHostReverseProxy(target)

	orig := rp.Director
	rp.Director = func(r *http.Request) {
		// Original director sets Host/Scheme/Path; do that first.
		orig(r)
		r.Host = "openrouter.ai"
		r.URL.Path = "/api/v1/messages"

		// Translate auth header.
		if key := r.Header.Get("x-api-key"); key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
			r.Header.Del("x-api-key")
		}
		// anthropic-version is harmless against OpenRouter; leave it.
	}

	http.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		// Read the body once if you want to log the model name; otherwise just proxy.
		_, _ = io.Copy(io.Discard, http.NoBody)
		rp.ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe("127.0.0.1:8787", nil))
}
```

Same analyzer config as Option B.

## Verifying the proxy works

After deploying:

```bash
# Should return 200 with a JSON message, or 401 if the key is wrong.
curl -sf -X POST http://127.0.0.1:8787/v1/messages \
  -H "x-api-key: $OPENROUTER_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic/claude-haiku-4-5",
    "max_tokens": 16,
    "messages": [{"role":"user","content":"reply with the word ok"}]
  }' | jq .
```

A successful response includes `"content"`, `"stop_reason"`, and a `"usage"` block. If `usage.cache_creation_input_tokens` is missing entirely, the proxy is stripping a header — verify your config keeps the body unmodified.

After the analyzer is restarted with the proxy URL, watch the new metrics:

```promql
sum(rate(claude_input_tokens_total[5m])) > 0
sum(rate(claude_cache_read_tokens_total[5m])) > 0   # after the first repeated alert
```

If both are non-zero, the path is working end-to-end including caching.

## Caveats

- **Model names**: OpenRouter expects `anthropic/claude-sonnet-4-6` (provider-prefixed), Anthropic direct expects `claude-sonnet-4-6`. Set `CLAUDE_MODEL` and the per-severity overrides accordingly. Mixing forms across env vars will produce 404s on the wrong-shaped one.
- **Prompt caching across providers**: OpenRouter's Anthropic skin passes `cache_control` through. If OpenRouter fails over to a different provider mid-session, cached context is lost for that request. The analyzer doesn't pin providers; if cache hit rate is inexplicably low, consider OpenRouter's `:nitro` / no-failover routing options.
- **Latency**: one extra TCP hop. Negligible for the analyzer's use case (Claude calls already take seconds), but worth knowing.
- **Failure modes**: if OpenRouter is down, the proxy returns 502/504 — same handling path as a real Anthropic 5xx in the analyzer (retry + circuit-breaker once Phase 2 lands).

## Why we removed the built-in Bearer path

The analyzer used to detect `anthropic.com` URLs and switch auth header automatically. That branch was removed in Phase 1 because it (a) blocked clean prompt-caching headers, (b) added a divergent code path with non-trivial test surface, and (c) was implicit — operators couldn't tell from `API_BASE_URL` alone which auth shape would be sent. Pushing the auth-shape decision into a deliberate proxy is more honest and keeps the analyzer's surface area minimal.

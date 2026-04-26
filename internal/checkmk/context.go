package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// APIClient queries the CheckMK REST API.
type APIClient struct {
	HTTP   *http.Client
	URL    string
	User   string
	Secret string
}

// NewAPIClient creates a client from config with default 10s timeout.
// The URL is normalised to always end with "/" so that path concatenation
// (e.g. url+"objects/host_config/"+hostname) produces a valid URL regardless
// of whether the operator included a trailing slash in CHECKMK_API_URL.
func NewAPIClient(cfg Config) *APIClient {
	apiURL := cfg.CheckMKAPIURL
	if !strings.HasSuffix(apiURL, "/") {
		apiURL += "/"
	}
	return &APIClient{
		HTTP:   &http.Client{Timeout: 10 * time.Second},
		URL:    apiURL,
		User:   cfg.CheckMKAPIUser,
		Secret: cfg.CheckMKAPISecret,
	}
}

// validHostnameRe matches DNS hostnames, FQDNs, and IPv4 addresses.
// It rejects path separators, whitespace, null bytes, and URL-encoding.
// The middle group uses {0,251} so the total length is at most 1+251+1 = 253
// characters, matching the RFC 1035 limit for a fully-qualified domain name.
var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,251}[a-zA-Z0-9])?$`)

func isValidHostname(hostname string) bool {
	// Reject consecutive dots (invalid in DNS labels) before applying the regex.
	if strings.Contains(hostname, "..") {
		return false
	}
	return validHostnameRe.MatchString(hostname)
}

type checkmkHostResponse struct {
	ID         string                `json:"id"`
	Extensions checkmkHostExtensions `json:"extensions"`
}

type checkmkHostExtensions struct {
	Attributes checkmkHostAttributes `json:"attributes"`
}

type checkmkHostAttributes struct {
	IPAddress       string `json:"ipaddress"`
	IPAddressFamily string `json:"ip_address_family"`
	AIContext       string `json:"ai_context"`
}

// HostInfo holds host metadata extracted from the CheckMK API.
type HostInfo struct {
	AIContext  string
	VerifiedIP string // IP address confirmed by CheckMK; use this as the SSH dial target
}

type checkmkServiceEntry struct {
	Extensions checkmkServiceExtensions `json:"extensions"`
}

type checkmkServiceExtensions struct {
	Description string `json:"description"`
	State       int    `json:"state"`
	Output      string `json:"plugin_output"`
}

type checkmkServicesResponse struct {
	Value []checkmkServiceEntry `json:"value"`
}

const maxAIContextBytes = 2048

// sanitizeHostContext trims, strips control characters, and truncates.
// Tabs and newlines are preserved because they carry formatting intent in
// operator-provided multi-line host context. Carriage returns (\r) are
// dropped, so Windows-style CRLF line endings are normalised to bare \n.
func sanitizeHostContext(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\t' || r == '\n' || !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	s = strings.TrimSpace(b.String())
	if len(s) > maxAIContextBytes {
		// Reserve space for the marker so the total stays within maxAIContextBytes,
		// matching the same accounting done in shared.Truncate. strings.ToValidUTF8
		// trims to a valid UTF-8 boundary to avoid splitting multi-byte characters.
		const marker = " [truncated]"
		cutAt := maxAIContextBytes - len(marker)
		s = strings.ToValidUTF8(s[:cutAt], "") + marker
	}
	return s
}

// sanitizePluginOutput strips control characters from multi-line plugin output
// while preserving newlines and tabs, before it is injected into the Claude
// prompt. long_plugin_output is expected to be multi-line formatted text, so
// newlines and tabs must be kept intact. However, carriage returns, null bytes,
// ESC (and other C0 characters), DEL, and C1 Unicode control characters
// (U+0080–U+009F) are stripped — they serve no diagnostic purpose and could
// be used to corrupt prompt formatting (e.g. ANSI escape sequences) or for
// terminal-side prompt injection techniques.
func sanitizePluginOutput(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' || !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeAlertField strips all control characters from a single-line alert
// field value before it is injected into the Claude prompt. Fields like
// hostname, service name, and notification type are single-line identifiers —
// embedded newlines or other control characters in these values could inject
// fake Markdown sections into the prompt (prompt injection). Unlike
// sanitizeHostContext, tabs and newlines are also stripped because these fields
// are expected to be single-line identifiers, not formatted text.
func sanitizeAlertField(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func (c *APIClient) ValidateAndDescribeHost(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
	if !isValidHostname(hostname) {
		return nil, fmt.Errorf("invalid hostname %q", hostname)
	}
	u := fmt.Sprintf("%sobjects/host_config/%s", c.URL, hostname)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s %s", c.User, c.Secret))
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CheckMK API request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, shared.MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("host %q not found in CheckMK", hostname)
	}
	if resp.StatusCode != http.StatusOK {
		// Include a redacted snippet of the body so operators can diagnose
		// auth failures (401/403), gateway errors (502/503), or misconfigurations
		// without having to replay the request manually. Mirrors the pattern
		// used in sendRequest (claude.go) for non-200 API responses.
		return nil, fmt.Errorf("CheckMK API returned %d for host %q: %s",
			resp.StatusCode, hostname,
			shared.Truncate(shared.RedactSecrets(strings.TrimSpace(string(body))), 200))
	}

	var hostResp checkmkHostResponse
	if err := json.Unmarshal(body, &hostResp); err != nil {
		return nil, fmt.Errorf("parse host response: %w", err)
	}

	info := &HostInfo{
		AIContext: hostResp.Extensions.Attributes.AIContext,
	}

	knownAddress := hostResp.Extensions.Attributes.IPAddress
	if knownAddress == "" {
		return info, fmt.Errorf("host %q has no IP address configured in CheckMK", hostname)
	}
	if knownAddress != hostAddress {
		return info, fmt.Errorf("host_address %q does not match CheckMK-known address %q for host %q", hostAddress, knownAddress, hostname)
	}

	info.VerifiedIP = knownAddress
	return info, nil
}

// serviceEntry pairs a CheckMK state value with its formatted output line.
// Used to sort non-OK services by severity before applying truncation.
type serviceEntry struct {
	state int
	line  string
}

// nonOKPriority returns a sort key that orders CheckMK state values by
// diagnostic importance. CRIT (2) sorts first, WARN (1) second, UNKNOWN (3)
// third, and any other non-OK state last. When non-OK service count exceeds
// maxServiceLines, sorting ensures the most critical entries survive truncation
// regardless of the order the CheckMK API returns them.
func nonOKPriority(state int) int {
	switch state {
	case 2:
		return 0 // CRIT — highest priority
	case 1:
		return 1 // WARN
	case 3:
		return 2 // UNKNOWN
	default:
		return 3 // other non-OK state (stale, pending, …)
	}
}

func (c *APIClient) GetHostServices(ctx context.Context, hostname string) string {
	if !isValidHostname(hostname) {
		return fmt.Sprintf("(invalid hostname %q)", hostname)
	}
	u := fmt.Sprintf("%sobjects/host/%s/collections/services", c.URL, hostname)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return fmt.Sprintf("(request error: %v)", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s %s", c.User, c.Secret))
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Sprintf("(CheckMK API failed: %v)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, shared.MaxResponseBytes))
	if err != nil {
		return "(failed to read response)"
	}

	if resp.StatusCode != http.StatusOK {
		// Include a redacted snippet so operators can diagnose auth failures
		// (401/403), gateway errors (502/503), or misconfigurations without
		// replaying the request. Mirrors the same pattern in ValidateAndDescribeHost.
		// The body has already been read above to drain the connection for reuse.
		return fmt.Sprintf("(CheckMK API returned %d: %s)", resp.StatusCode,
			shared.Truncate(shared.RedactSecrets(strings.TrimSpace(string(body))), 200))
	}

	var svcResp checkmkServicesResponse
	if err := json.Unmarshal(body, &svcResp); err != nil {
		return fmt.Sprintf("(failed to parse: %v)", err)
	}

	// Build two slices during construction: non-OK services first so that if
	// truncation is needed the least diagnostically relevant (OK) entries are
	// dropped. Separating by state here avoids a post-hoc substring search on
	// the formatted line, which would misclassify a service whose description
	// itself contains the literal text ": OK —".
	var nonOKEntries []serviceEntry
	var okLines []string
	stateNames := map[int]string{0: "OK", 1: "WARN", 2: "CRIT", 3: "UNKNOWN"}
	for _, svc := range svcResp.Value {
		state := stateNames[svc.Extensions.State]
		if state == "" {
			state = fmt.Sprintf("%d", svc.Extensions.State)
		}
		output := sanitizeAlertField(shared.RedactSecrets(svc.Extensions.Output))
		line := fmt.Sprintf("- %s: %s — %s", sanitizeAlertField(svc.Extensions.Description), state, output)
		if svc.Extensions.State == 0 {
			okLines = append(okLines, line)
		} else {
			nonOKEntries = append(nonOKEntries, serviceEntry{state: svc.Extensions.State, line: line})
		}
	}

	// Sort non-OK entries by severity so that when truncation is needed, the
	// most critical services are always preserved regardless of API return order.
	sort.Slice(nonOKEntries, func(i, j int) bool {
		return nonOKPriority(nonOKEntries[i].state) < nonOKPriority(nonOKEntries[j].state)
	})
	nonOKLines := make([]string, len(nonOKEntries))
	for i, e := range nonOKEntries {
		nonOKLines[i] = e.line
	}

	lines := append(nonOKLines, okLines...)

	if len(lines) == 0 {
		return "(no services found)"
	}

	// Cap the number of service lines injected into the Claude prompt.
	// CheckMK hosts can have hundreds of monitored services; sending all of
	// them consumes unnecessary tokens. Because nonOKLines are sorted by
	// severity (CRIT → WARN → UNKNOWN) and precede okLines, truncation always
	// drops the least diagnostically relevant entries first.
	const maxServiceLines = 100
	total := len(lines)
	if total > maxServiceLines {
		lines = append(lines[:maxServiceLines], fmt.Sprintf("... [%d more services truncated]", total-maxServiceLines))
	}

	return strings.Join(lines, "\n")
}

// GatherContext collects alert details and CheckMK host services.
// SSH diagnostics are handled separately by RunAgenticDiagnostics.
func GatherContext(ctx context.Context, apiClient *APIClient, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	var sections []shared.ContextSection

	if hostInfo != nil {
		if cleaned := sanitizeHostContext(hostInfo.AIContext); cleaned != "" {
			sections = append(sections, shared.ContextSection{
				Name:    "Host Context (operator-provided)",
				Content: shared.RedactSecrets(cleaned),
			})
		}
	}

	alertDetails := fmt.Sprintf("- Hostname: %s\n- Address: %s\n- Host State: %s\n- Service: %s\n- State: %s\n- Output: %s\n- Type: %s\n- Perf Data: %s\n- Timestamp: %s",
		sanitizeAlertField(hostname), sanitizeAlertField(hostAddress),
		sanitizeAlertField(alert.Fields["host_state"]),
		sanitizeAlertField(alert.Fields["service_description"]),
		sanitizeAlertField(alert.Fields["service_state"]),
		sanitizeAlertField(shared.RedactSecrets(alert.Fields["service_output"])),
		sanitizeAlertField(alert.Fields["notification_type"]),
		sanitizeAlertField(shared.RedactSecrets(alert.Fields["perf_data"])),
		sanitizeAlertField(alert.Fields["timestamp"]))
	// long_plugin_output can be very large (multi-line check details up to the 1 MiB
	// webhook body limit). Truncate to 4 KiB so a single verbose plugin does not
	// exhaust the Claude context window or inflate analysis costs unnecessarily.
	if lpo := shared.Truncate(shared.RedactSecrets(sanitizePluginOutput(alert.Fields["long_plugin_output"])), 4096); lpo != "" {
		alertDetails += "\n- Detailed Output:\n" + lpo
	}

	sections = append(sections, shared.ContextSection{
		Name:    "Alert Details",
		Content: alertDetails,
	})

	sections = append(sections, shared.ContextSection{
		Name:    "CheckMK Services on Host",
		Content: apiClient.GetHostServices(ctx, hostname),
	})

	return shared.AnalysisContext{Sections: sections}
}

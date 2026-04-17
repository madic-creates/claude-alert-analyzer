package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
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
func NewAPIClient(cfg Config) *APIClient {
	return &APIClient{
		HTTP:   &http.Client{Timeout: 10 * time.Second},
		URL:    cfg.CheckMKAPIURL,
		User:   cfg.CheckMKAPIUser,
		Secret: cfg.CheckMKAPISecret,
	}
}

// validHostnameRe matches DNS hostnames, FQDNs, and IPv4 addresses.
// It rejects path separators, whitespace, null bytes, and URL-encoding.
var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$`)

func isValidHostname(hostname string) bool {
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
	AIContext string
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
func sanitizeHostContext(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\t' || !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	s = strings.TrimSpace(b.String())
	if len(s) > maxAIContextBytes {
		// Truncate at a valid UTF-8 boundary to avoid splitting multi-byte characters.
		s = strings.ToValidUTF8(s[:maxAIContextBytes], "") + " [truncated]"
	}
	return s
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
		return nil, fmt.Errorf("CheckMK API returned %d for host %q", resp.StatusCode, hostname)
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

	return info, nil
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
		return fmt.Sprintf("(CheckMK API returned %d)", resp.StatusCode)
	}

	var svcResp checkmkServicesResponse
	if err := json.Unmarshal(body, &svcResp); err != nil {
		return fmt.Sprintf("(failed to parse: %v)", err)
	}

	var lines []string
	stateNames := map[int]string{0: "OK", 1: "WARN", 2: "CRIT", 3: "UNKNOWN"}
	for _, svc := range svcResp.Value {
		state := stateNames[svc.Extensions.State]
		if state == "" {
			state = fmt.Sprintf("%d", svc.Extensions.State)
		}
		output := shared.RedactSecrets(svc.Extensions.Output)
		line := fmt.Sprintf("- %s: %s — %s", svc.Extensions.Description, state, output)
		lines = append(lines, line)
	}

	if len(lines) == 0 {
		return "(no services found)"
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
				Content: cleaned,
			})
		}
	}

	sections = append(sections, shared.ContextSection{
		Name: "Alert Details",
		Content: fmt.Sprintf("- Hostname: %s\n- Address: %s\n- Service: %s\n- State: %s\n- Output: %s\n- Type: %s\n- Perf Data: %s",
			hostname, hostAddress, alert.Fields["service_description"],
			alert.Fields["service_state"], alert.Fields["service_output"],
			alert.Fields["notification_type"], alert.Fields["perf_data"]),
	})

	sections = append(sections, shared.ContextSection{
		Name:    "CheckMK Services on Host",
		Content: apiClient.GetHostServices(ctx, hostname),
	})

	return shared.AnalysisContext{Sections: sections}
}

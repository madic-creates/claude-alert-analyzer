package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

var checkmkHTTPClient = &http.Client{Timeout: 10 * time.Second}

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

func ValidateAndDescribeHost(ctx context.Context, cfg Config, hostname, hostAddress string) (*HostInfo, error) {
	url := fmt.Sprintf("%sobjects/host_config/%s", cfg.CheckMKAPIURL, hostname)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s %s", cfg.CheckMKAPIUser, cfg.CheckMKAPISecret))
	req.Header.Set("Accept", "application/json")

	resp, err := checkmkHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CheckMK API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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

	knownAddress := hostResp.Extensions.Attributes.IPAddress
	if knownAddress == "" {
		return nil, fmt.Errorf("host %q has no IP address configured in CheckMK", hostname)
	}
	if knownAddress != hostAddress {
		return nil, fmt.Errorf("host_address %q does not match CheckMK-known address %q for host %q", hostAddress, knownAddress, hostname)
	}

	return &HostInfo{
		AIContext: hostResp.Extensions.Attributes.AIContext,
	}, nil
}

func getHostServices(ctx context.Context, cfg Config, hostname string) string {
	url := fmt.Sprintf("%sobjects/host/%s/collections/services", cfg.CheckMKAPIURL, hostname)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Sprintf("(request error: %v)", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s %s", cfg.CheckMKAPIUser, cfg.CheckMKAPISecret))
	req.Header.Set("Accept", "application/json")

	resp, err := checkmkHTTPClient.Do(req)
	if err != nil {
		return fmt.Sprintf("(CheckMK API failed: %v)", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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
		line := fmt.Sprintf("- %s: %s — %s", svc.Extensions.Description, state, svc.Extensions.Output)
		lines = append(lines, line)
	}

	if len(lines) == 0 {
		return "(no services found)"
	}
	return strings.Join(lines, "\n")
}

// GatherContext collects alert details and CheckMK host services.
// SSH diagnostics are handled separately by RunAgenticDiagnostics.
func GatherContext(ctx context.Context, cfg Config, alert shared.AlertPayload) shared.AnalysisContext {
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	var sections []shared.ContextSection

	sections = append(sections, shared.ContextSection{
		Name: "Alert Details",
		Content: fmt.Sprintf("- Hostname: %s\n- Address: %s\n- Service: %s\n- State: %s\n- Output: %s\n- Type: %s\n- Perf Data: %s",
			hostname, hostAddress, alert.Fields["service_description"],
			alert.Fields["service_state"], alert.Fields["service_output"],
			alert.Fields["notification_type"], alert.Fields["perf_data"]),
	})

	sections = append(sections, shared.ContextSection{
		Name:    "CheckMK Services on Host",
		Content: getHostServices(ctx, cfg, hostname),
	})

	return shared.AnalysisContext{Sections: sections}
}

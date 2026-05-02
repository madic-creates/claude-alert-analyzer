package checkmk

import "github.com/madic-creates/claude-alert-analyzer/internal/shared"

type CheckMKNotification struct {
	Hostname           string `json:"hostname"`
	HostAddress        string `json:"host_address"`
	ServiceDescription string `json:"service_description"`
	ServiceState       string `json:"service_state"`
	ServiceOutput      string `json:"service_output"`
	HostState          string `json:"host_state"`
	NotificationType   string `json:"notification_type"`
	PerfData           string `json:"perf_data"`
	LongPluginOutput   string `json:"long_plugin_output"`
	Timestamp          string `json:"timestamp"`
}

type Config struct {
	ClaudeModel       string
	CooldownSeconds   int
	Port              string
	MetricsPort       string
	WebhookSecret     string
	APIBaseURL        string
	APIKey            string
	CheckMKAPIURL     string
	CheckMKAPIUser    string
	CheckMKAPISecret  string
	SSHEnabled        bool
	SSHUser           string
	SSHKeyPath        string
	SSHKnownHostsPath string
	SSHDeniedCommands map[string]bool // nil = use default, empty = no guardrails
}

// BaseConfig returns a shared.BaseConfig derived from this Config.
func (c Config) BaseConfig() shared.BaseConfig {
	return shared.BaseConfig{
		ClaudeModel:     c.ClaudeModel,
		CooldownSeconds: c.CooldownSeconds,
		Port:            c.Port,
		MetricsPort:     c.MetricsPort,
		WebhookSecret:   c.WebhookSecret,
		APIBaseURL:      c.APIBaseURL,
		APIKey:          c.APIKey,
	}
}

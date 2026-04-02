package checkmk

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
	NtfyPublishURL    string
	NtfyPublishTopic  string
	NtfyPublishToken  string
	ClaudeModel       string
	CooldownSeconds   int
	Port              string
	WebhookSecret     string
	APIBaseURL        string
	APIKey            string
	CheckMKAPIURL     string
	CheckMKAPIUser    string
	CheckMKAPISecret  string
	SSHUser           string
	SSHKeyPath        string
	SSHKnownHostsPath string
}

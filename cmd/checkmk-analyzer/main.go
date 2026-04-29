package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/checkmk"
	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

func loadConfig() checkmk.Config {
	cooldown, err := shared.ParseIntEnv("COOLDOWN_SECONDS", "300", 0, 86400)
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}
	maxAgentRounds, err := shared.ParseIntEnv("MAX_AGENT_ROUNDS", "10", 1, 50)
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}

	webhookSecret, err := shared.RequireEnv("WEBHOOK_SECRET")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}
	apiKey, err := shared.RequireEnv("API_KEY")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}
	checkmkUser, err := shared.RequireEnv("CHECKMK_API_USER")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}
	checkmkSecret, err := shared.RequireEnv("CHECKMK_API_SECRET")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	// SSH_DENIED_COMMANDS: not set = default denylist, empty = no guardrails, value = custom list
	var sshDeniedCommands map[string]bool
	if val, ok := os.LookupEnv("SSH_DENIED_COMMANDS"); ok {
		sshDeniedCommands = make(map[string]bool)
		for _, cmd := range strings.Split(val, ",") {
			cmd = strings.ToLower(strings.TrimSpace(cmd))
			if cmd != "" {
				sshDeniedCommands[cmd] = true
			}
		}
		if len(sshDeniedCommands) == 0 {
			slog.Warn("SSH_DENIED_COMMANDS is set but resolved to empty — all commands are allowed, no denylist active")
		}
	}

	return checkmk.Config{
		ClaudeModel:       shared.EnvOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds:   cooldown,
		Port:              shared.EnvOrDefault("PORT", "8080"),
		MetricsPort:       shared.EnvOrDefault("METRICS_PORT", "9101"),
		WebhookSecret:     webhookSecret,
		APIBaseURL:        shared.EnvOrDefault("API_BASE_URL", "https://api.anthropic.com/v1/messages"),
		APIKey:            apiKey,
		CheckMKAPIURL:     shared.EnvOrDefault("CHECKMK_API_URL", "http://checkmk-service.monitoring:5000/cmk/check_mk/api/1.0/"),
		CheckMKAPIUser:    checkmkUser,
		CheckMKAPISecret:  checkmkSecret,
		SSHEnabled:        shared.EnvOrDefault("SSH_ENABLED", "true") == "true",
		SSHUser:           shared.EnvOrDefault("SSH_USER", "nagios"),
		SSHKeyPath:        shared.EnvOrDefault("SSH_KEY_PATH", "/ssh/id_ed25519"),
		SSHKnownHostsPath: shared.EnvOrDefault("SSH_KNOWN_HOSTS_PATH", "/ssh/known_hosts"),
		SSHDeniedCommands: sshDeniedCommands,
		MaxAgentRounds:    maxAgentRounds,
	}
}

func main() {
	var logLevel slog.Level
	switch strings.ToLower(shared.EnvOrDefault("LOG_LEVEL", "info")) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	cfg := loadConfig()

	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}
	claudeClient := shared.NewClaudeClient(cfg.BaseConfig()).WithPrometheusMetrics(metrics, "checkmk")
	apiClient := checkmk.NewAPIClient(cfg)
	cooldownMgr := shared.NewCooldownManager()
	publishers := []shared.Publisher{
		shared.NewNtfyPublisher(
			shared.EnvOrDefault("NTFY_PUBLISH_URL", "https://ntfy.example.com"),
			shared.EnvOrDefault("NTFY_PUBLISH_TOPIC", "checkmk-analysis"),
			os.Getenv("NTFY_PUBLISH_TOKEN"),
		),
	}

	var sshDialer checkmk.Dialer
	if cfg.SSHEnabled {
		var err error
		sshDialer, err = checkmk.NewSSHDialer(cfg)
		if err != nil {
			slog.Error("SSH dialer init failed", "error", err)
			os.Exit(1)
		}
	}

	deps := checkmk.PipelineDeps{
		Analyzer:   claudeClient,
		ToolRunner: claudeClient,
		Publishers: publishers,
		Cooldown:   cooldownMgr,
		Metrics:    metrics,
		SSHEnabled: cfg.SSHEnabled,
		SSHDialer:  sshDialer,
		SSHConfig:  cfg,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *checkmk.HostInfo) shared.AnalysisContext {
			return checkmk.GatherContext(ctx, apiClient, alert, hostInfo)
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*checkmk.HostInfo, error) {
			return apiClient.ValidateAndDescribeHost(ctx, hostname, hostAddress)
		},
	}

	srv := shared.NewServer(shared.ServerConfig{
		Port:         cfg.Port,
		MetricsPort:  cfg.MetricsPort,
		WorkerCount:  5,
		QueueSize:    20,
		DrainTimeout: 25 * time.Second,
		Source:       "checkmk",
	}, metrics, func(ctx context.Context, alert shared.AlertPayload) {
		checkmk.ProcessAlert(ctx, deps, alert)
	})

	slog.Info("CheckMK Alert Analyzer started",
		"port", cfg.Port, "metricsPort", cfg.MetricsPort, "model", cfg.ClaudeModel,
		"apiBaseURL", cfg.APIBaseURL,
		"checkmkAPI", cfg.CheckMKAPIURL,
		"sshEnabled", cfg.SSHEnabled,
		"maxAgentRounds", cfg.MaxAgentRounds)

	handler := checkmk.HandleWebhook(cfg, cooldownMgr, srv.Enqueue, metrics)
	srv.Run(handler)
}

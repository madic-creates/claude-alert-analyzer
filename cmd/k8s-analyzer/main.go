package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/k8s"
	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func loadConfig() k8s.Config {
	cooldown, err := shared.ParseIntEnv("COOLDOWN_SECONDS", "300", 0, 86400)
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}
	maxLogBytes, err := shared.ParseIntEnv("MAX_LOG_BYTES", "2048", 256, 1048576)
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}
	webhookSecret, err := shared.RequireEnv("WEBHOOK_SECRET")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	authToken := os.Getenv("ANTHROPIC_AUTH_TOKEN")
	baseURL := os.Getenv("ANTHROPIC_BASE_URL")

	switch {
	case apiKey == "" && authToken == "":
		slog.Error("config error", "error", "either ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN must be set")
		os.Exit(1)
	case apiKey != "" && authToken != "":
		slog.Error("config error", "error", "set exactly one of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN, not both")
		os.Exit(1)
	}

	// Unset the three vars so the SDK never falls back to its own env-var
	// lookups; main.go is the single source of truth.
	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
	_ = os.Unsetenv("ANTHROPIC_BASE_URL")

	return k8s.Config{
		PrometheusURL:   shared.EnvOrDefault("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"),
		ClaudeModel:     shared.EnvOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds: cooldown,
		SkipResolved:    shared.EnvOrDefault("SKIP_RESOLVED", "true") != "false",
		Port:            shared.EnvOrDefault("PORT", "8080"),
		MetricsPort:     shared.EnvOrDefault("METRICS_PORT", "9101"),
		WebhookSecret:   webhookSecret,
		MaxLogBytes:     maxLogBytes,
		APIBaseURL:      baseURL,
		APIKey:          apiKey,
		AuthToken:       authToken,
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

	policy, err := shared.LoadPolicy(cfg.BaseConfig())
	if err != nil {
		slog.Error("policy config", "error", err)
		os.Exit(1)
	}

	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("k8s config failed", "error", err)
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		slog.Error("k8s client failed", "error", err)
		os.Exit(1)
	}

	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}
	hist := metrics.Prom.ClaudeAPIDuration.WithLabelValues("k8s")
	transport := shared.NewLimitedTransport(http.DefaultTransport, hist)
	claudeClient := shared.NewClaudeClient(cfg.BaseConfig(), transport).WithPrometheusMetrics(metrics, "k8s")
	promClient := k8s.NewPrometheusClient(cfg.PrometheusURL)
	cooldownMgr := shared.NewCooldownManager()
	publishers := []shared.Publisher{
		shared.NewNtfyPublisher(
			shared.EnvOrDefault("NTFY_PUBLISH_URL", "https://ntfy.example.com"),
			shared.EnvOrDefault("NTFY_PUBLISH_TOPIC", "kubernetes-analysis"),
			os.Getenv("NTFY_PUBLISH_TOKEN"),
		),
	}

	deps := k8s.PipelineDeps{
		Analyzer:      claudeClient,
		ToolRunner:    claudeClient,
		KubectlRunner: k8s.NewKubectlSubprocess(""),
		Prom:          promClient,
		Publishers:    publishers,
		Cooldown:      cooldownMgr,
		Metrics:       metrics,
		Policy:        policy,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return k8s.GatherContext(ctx, promClient, clientset, k8s.AlertPayloadToAlert(alert), cfg)
		},
	}

	if deps.Analyzer == nil || deps.ToolRunner == nil || deps.Policy == nil ||
		deps.Cooldown == nil || deps.Metrics == nil || deps.GatherContext == nil ||
		deps.KubectlRunner == nil || deps.Prom == nil {
		slog.Error("k8s pipeline deps incomplete — refusing to start")
		os.Exit(1)
	}

	srv := shared.NewServer(shared.ServerConfig{
		Port:         cfg.Port,
		MetricsPort:  cfg.MetricsPort,
		WorkerCount:  5,
		QueueSize:    20,
		DrainTimeout: 25 * time.Second,
		Source:       "k8s",
	}, metrics, func(ctx context.Context, alert shared.AlertPayload) {
		k8s.ProcessAlert(ctx, deps, alert)
	})

	slog.Info("K8s Alert Analyzer started",
		"port", cfg.Port, "metricsPort", cfg.MetricsPort, "model", cfg.ClaudeModel,
		"apiBaseURL", cfg.APIBaseURL,
		"defaultRounds", policy.DefaultMaxRounds,
		"modelOverrides", len(policy.ModelOverrides),
		"roundsOverrides", len(policy.RoundsOverrides))

	handler := k8s.HandleWebhook(cfg, cooldownMgr, srv.Enqueue, metrics)
	srv.Run(handler)
}

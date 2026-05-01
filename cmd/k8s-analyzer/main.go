package main

import (
	"context"
	"log/slog"
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
	apiKey, err := shared.RequireEnv("API_KEY")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	return k8s.Config{
		PrometheusURL:   shared.EnvOrDefault("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"),
		ClaudeModel:     shared.EnvOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds: cooldown,
		SkipResolved:    shared.EnvOrDefault("SKIP_RESOLVED", "true") != "false",
		Port:            shared.EnvOrDefault("PORT", "8080"),
		MetricsPort:     shared.EnvOrDefault("METRICS_PORT", "9101"),
		WebhookSecret:   webhookSecret,
		MaxLogBytes:     maxLogBytes,
		APIBaseURL:      shared.EnvOrDefault("API_BASE_URL", "https://api.anthropic.com/v1/messages"),
		APIKey:          apiKey,
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
	claudeClient := shared.NewClaudeClient(cfg.BaseConfig()).WithPrometheusMetrics(metrics, "k8s")
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
		ToolRunner:     claudeClient,
		KubectlRunner:  k8s.NewKubectlSubprocess(""),
		Prom:           promClient,
		Publishers:     publishers,
		Cooldown:       cooldownMgr,
		Metrics:        metrics,
		MaxAgentRounds: cfg.MaxAgentRounds,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return k8s.GatherContext(ctx, promClient, clientset, k8s.AlertPayloadToAlert(alert), cfg)
		},
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
		"apiBaseURL", cfg.APIBaseURL)

	handler := k8s.HandleWebhook(cfg, cooldownMgr, srv.Enqueue, metrics)
	srv.Run(handler)
}

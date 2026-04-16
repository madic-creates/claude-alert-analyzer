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

const systemPrompt = `You are a Kubernetes SRE analyst for a k3s home cluster with Prometheus, Grafana, Longhorn storage, Traefik ingress, and Cilium CNI.

Analyze the provided alert with its cluster context and produce a concise root-cause analysis:
1. Identify the most likely root cause
2. Assess severity and blast radius
3. Suggest concrete remediation steps (kubectl commands, config changes)
4. Note correlations with other active alerts

Keep response under 500 words. Use markdown for formatting (headings, bold, lists, code blocks) but never use markdown tables. Use bullet lists instead of tables. Reference actual metric values and pod names.
Start directly with the analysis — no preamble, meta-commentary, or introductory sentences like "I have enough data" or "Let me analyze this".`

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

	allowedNS := shared.EnvOrDefault("ALLOWED_NAMESPACES", "monitoring,databases,media")
	var nsList []string
	for _, ns := range strings.Split(allowedNS, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			nsList = append(nsList, ns)
		}
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
		PrometheusURL:     shared.EnvOrDefault("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"),
		ClaudeModel:       shared.EnvOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds:   cooldown,
		SkipResolved:      shared.EnvOrDefault("SKIP_RESOLVED", "true") != "false",
		Port:              shared.EnvOrDefault("PORT", "8080"),
		WebhookSecret:     webhookSecret,
		AllowedNamespaces: nsList,
		MaxLogBytes:       maxLogBytes,
		APIBaseURL:        shared.EnvOrDefault("API_BASE_URL", "https://api.anthropic.com/v1/messages"),
		APIKey:            apiKey,
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

	logFormat := shared.EnvOrDefault("LOG_FORMAT", "text")
	var logHandler slog.Handler
	if logFormat == "json" {
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}
	slog.SetDefault(slog.New(logHandler))

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

	claudeClient := shared.NewClaudeClient(cfg.BaseConfig())
	promClient := k8s.NewPrometheusClient(cfg.PrometheusURL)
	cooldownMgr := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)
	publishers := []shared.Publisher{
		shared.NewNtfyPublisher(
			shared.EnvOrDefault("NTFY_PUBLISH_URL", "https://ntfy.example.com"),
			shared.EnvOrDefault("NTFY_PUBLISH_TOPIC", "kubernetes-analysis"),
			os.Getenv("NTFY_PUBLISH_TOKEN"),
		),
	}

	deps := k8s.PipelineDeps{
		Analyzer:     claudeClient,
		Publishers:   publishers,
		Cooldown:     cooldownMgr,
		Metrics:      metrics,
		SystemPrompt: systemPrompt,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			k8sAlert := alertPayloadToK8sAlert(alert)
			return k8s.GatherContext(ctx, promClient, clientset, k8sAlert, cfg)
		},
	}

	srv := shared.NewServer(shared.ServerConfig{
		Port:         cfg.Port,
		WorkerCount:  5,
		QueueSize:    20,
		DrainTimeout: 25 * time.Second,
	}, metrics, func(ctx context.Context, alert shared.AlertPayload) {
		k8s.ProcessAlert(ctx, deps, alert)
	})

	slog.Info("K8s Alert Analyzer started",
		"port", cfg.Port, "model", cfg.ClaudeModel,
		"apiBaseURL", cfg.APIBaseURL,
		"allowedNamespaces", cfg.AllowedNamespaces)

	handler := k8s.HandleWebhook(cfg, cooldownMgr, srv.Enqueue, metrics)
	srv.Run(handler)
}

func alertPayloadToK8sAlert(ap shared.AlertPayload) k8s.Alert {
	alert := k8s.Alert{
		Status:      ap.Fields["status"],
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
		Fingerprint: ap.Fingerprint,
	}
	for key, v := range ap.Fields {
		if strings.HasPrefix(key, "label:") {
			alert.Labels[strings.TrimPrefix(key, "label:")] = v
		} else if strings.HasPrefix(key, "annotation:") {
			alert.Annotations[strings.TrimPrefix(key, "annotation:")] = v
		}
	}
	return alert
}

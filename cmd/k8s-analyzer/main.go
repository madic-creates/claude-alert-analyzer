package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadConfig() k8s.Config {
	cooldown, _ := strconv.Atoi(envOrDefault("COOLDOWN_SECONDS", "300"))
	maxLogBytes, _ := strconv.Atoi(envOrDefault("MAX_LOG_BYTES", "2048"))

	allowedNS := envOrDefault("ALLOWED_NAMESPACES", "monitoring,databases,media")
	var nsList []string
	for _, ns := range strings.Split(allowedNS, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			nsList = append(nsList, ns)
		}
	}

	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	if webhookSecret == "" {
		slog.Error("WEBHOOK_SECRET is required")
		os.Exit(1)
	}
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		slog.Error("API_KEY is required")
		os.Exit(1)
	}

	return k8s.Config{
		PrometheusURL:     envOrDefault("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"),
		ClaudeModel:       envOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds:   cooldown,
		SkipResolved:      envOrDefault("SKIP_RESOLVED", "true") != "false",
		Port:              envOrDefault("PORT", "8080"),
		WebhookSecret:     webhookSecret,
		AllowedNamespaces: nsList,
		MaxLogBytes:       maxLogBytes,
		APIBaseURL:        envOrDefault("API_BASE_URL", "https://api.anthropic.com/v1/messages"),
		APIKey:            apiKey,
	}
}

func buildPublishers() []shared.Publisher {
	var publishers []shared.Publisher

	ntfyURL := envOrDefault("NTFY_PUBLISH_URL", "https://ntfy.example.com")
	ntfyTopic := envOrDefault("NTFY_PUBLISH_TOPIC", "kubernetes-analysis")
	publishers = append(publishers, &shared.NtfyPublisher{
		URL:   ntfyURL,
		Topic: ntfyTopic,
		Token: os.Getenv("NTFY_PUBLISH_TOKEN"),
	})

	return publishers
}

func main() {
	cfg := loadConfig()
	publishers := buildPublishers()

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

	cooldownMgr := shared.NewCooldownManager()
	workerCtx, workerCancel := context.WithCancel(context.Background())
	metrics := new(shared.AlertMetrics)

	type workItem struct{ alert shared.AlertPayload }
	workQueue := make(chan workItem, 20)

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workQueue {
				processAlert(workerCtx, cfg, publishers, clientset, cooldownMgr, metrics, item.alert)
			}
		}()
	}

	webhookHandler := k8s.HandleWebhook(cfg, cooldownMgr, func(ap shared.AlertPayload) bool {
		select {
		case workQueue <- workItem{alert: ap}:
			metrics.AlertsQueued.Add(1)
			return true
		default:
			metrics.AlertsQueueFull.Add(1)
			return false
		}
	}, metrics)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("GET /metrics", metrics.MetricsHandler())
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		metrics.WebhooksReceived.Add(1)
		webhookHandler(w, r)
	})

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("K8s Alert Analyzer started",
			"port", cfg.Port, "model", cfg.ClaudeModel,
			"apiBaseURL", cfg.APIBaseURL,
			"allowedNamespaces", cfg.AllowedNamespaces)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	close(workQueue)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("all workers finished")
	case <-time.After(25 * time.Second):
		slog.Warn("worker drain timeout, cancelling")
		workerCancel()
		wg.Wait()
	}
	slog.Info("shutdown complete")
}

func processAlert(ctx context.Context, cfg k8s.Config, publishers []shared.Publisher, clientset kubernetes.Interface, cooldownMgr *shared.CooldownManager, metrics *shared.AlertMetrics, alert shared.AlertPayload) {
	alertname := alert.Title
	namespace := alert.Fields["label:namespace"]
	slog.Info("processing alert", "alertname", alertname, "namespace", namespace)

	// Reconstruct k8s.Alert from AlertPayload for context gathering
	k8sAlert := k8s.Alert{
		Status:      alert.Fields["status"],
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
		Fingerprint: alert.Fingerprint,
	}
	for k, v := range alert.Fields {
		if strings.HasPrefix(k, "label:") {
			k8sAlert.Labels[strings.TrimPrefix(k, "label:")] = v
		} else if strings.HasPrefix(k, "annotation:") {
			k8sAlert.Annotations[strings.TrimPrefix(k, "annotation:")] = v
		}
	}

	actx := k8s.GatherContext(ctx, clientset, cfg.PrometheusURL, k8sAlert, cfg)

	baseCfg := cfg.BaseConfig()
	userPrompt := fmt.Sprintf("## Alert: %s\n- Status: %s\n- Severity: %s\n- Namespace: %s\n\n%s",
		alertname, alert.Fields["status"], alert.Severity, namespace, actx.FormatForPrompt())

	analysis, err := shared.AnalyzeWithClaude(ctx, baseCfg, systemPrompt, userPrompt)
	if err != nil {
		slog.Error("analysis failed", "alertname", alertname, "error", err)
		_ = shared.PublishAll(ctx, publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alertname, err))
		cooldownMgr.Clear(alert.Fingerprint)
		metrics.AlertsFailed.Add(1)
		return
	}

	title := fmt.Sprintf("Analysis: %s", alertname)
	if namespace != "" {
		title = fmt.Sprintf("Analysis: %s (%s)", alertname, namespace)
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "info": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	if err := shared.PublishAll(ctx, publishers, title, priority, analysis); err != nil {
		cooldownMgr.Clear(alert.Fingerprint)
		metrics.AlertsFailed.Add(1)
		return
	}

	metrics.AlertsProcessed.Add(1)
	slog.Info("analysis complete", "alertname", alertname, "model", cfg.ClaudeModel)
}

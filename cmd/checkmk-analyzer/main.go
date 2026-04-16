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

	"github.com/madic-creates/claude-alert-analyzer/internal/checkmk"
	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadConfig() checkmk.Config {
	cooldown, _ := strconv.Atoi(envOrDefault("COOLDOWN_SECONDS", "300"))
	maxAgentRounds, _ := strconv.Atoi(envOrDefault("MAX_AGENT_ROUNDS", "10"))

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
	checkmkUser := os.Getenv("CHECKMK_API_USER")
	if checkmkUser == "" {
		slog.Error("CHECKMK_API_USER is required")
		os.Exit(1)
	}
	checkmkSecret := os.Getenv("CHECKMK_API_SECRET")
	if checkmkSecret == "" {
		slog.Error("CHECKMK_API_SECRET is required")
		os.Exit(1)
	}

	// SSH_DENIED_COMMANDS: not set = default denylist, empty = no guardrails, value = custom list
	var sshDeniedCommands map[string]bool
	if val, ok := os.LookupEnv("SSH_DENIED_COMMANDS"); ok {
		sshDeniedCommands = make(map[string]bool)
		for _, cmd := range strings.Split(val, ",") {
			cmd = strings.TrimSpace(cmd)
			if cmd != "" {
				sshDeniedCommands[cmd] = true
			}
		}
	}

	return checkmk.Config{
		ClaudeModel:       envOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds:   cooldown,
		Port:              envOrDefault("PORT", "8080"),
		WebhookSecret:     webhookSecret,
		APIBaseURL:        envOrDefault("API_BASE_URL", "https://api.anthropic.com/v1/messages"),
		APIKey:            apiKey,
		CheckMKAPIURL:     envOrDefault("CHECKMK_API_URL", "http://checkmk-service.monitoring:5000/cmk/check_mk/api/1.0/"),
		CheckMKAPIUser:    checkmkUser,
		CheckMKAPISecret:  checkmkSecret,
		SSHEnabled:        envOrDefault("SSH_ENABLED", "true") == "true",
		SSHUser:           envOrDefault("SSH_USER", "nagios"),
		SSHKeyPath:        envOrDefault("SSH_KEY_PATH", "/ssh/id_ed25519"),
		SSHKnownHostsPath: envOrDefault("SSH_KNOWN_HOSTS_PATH", "/ssh/known_hosts"),
		SSHDeniedCommands: sshDeniedCommands,
		MaxAgentRounds:    maxAgentRounds,
	}
}

func buildPublishers() []shared.Publisher {
	var publishers []shared.Publisher

	publishers = append(publishers, shared.NewNtfyPublisher(
		envOrDefault("NTFY_PUBLISH_URL", "https://ntfy.example.com"),
		envOrDefault("NTFY_PUBLISH_TOPIC", "checkmk-analysis"),
		os.Getenv("NTFY_PUBLISH_TOKEN"),
	))

	return publishers
}

func main() {
	cfg := loadConfig()
	publishers := buildPublishers()
	cooldownMgr := shared.NewCooldownManager()
	claudeClient := shared.NewClaudeClient(cfg.BaseConfig())
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	metrics := new(shared.AlertMetrics)

	type workItem struct{ alert shared.AlertPayload }
	workQueue := make(chan workItem, 20)

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workQueue {
				processAlert(workerCtx, cfg, publishers, claudeClient, cooldownMgr, metrics, item.alert)
			}
		}()
	}

	webhookHandler := checkmk.HandleWebhook(cfg, cooldownMgr, func(ap shared.AlertPayload) bool {
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
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("CheckMK Alert Analyzer started",
			"port", cfg.Port, "model", cfg.ClaudeModel,
			"checkmkAPI", cfg.CheckMKAPIURL)
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

func processAlert(ctx context.Context, cfg checkmk.Config, publishers []shared.Publisher, claudeClient *shared.ClaudeClient, cooldownMgr *shared.CooldownManager, metrics *shared.AlertMetrics, alert shared.AlertPayload) {
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	slog.Info("processing CheckMK alert",
		"hostname", hostname,
		"service", alert.Fields["service_description"])

	// Fetch host metadata (including ai_context) and validate host identity
	hostInfo, validationErr := checkmk.ValidateAndDescribeHost(ctx, cfg, hostname, hostAddress)
	if validationErr != nil {
		slog.Warn("host validation failed", "error", validationErr, "hostname", hostname, "host_address", hostAddress)
	}

	// Gather CheckMK context (alert details + host services + optional host context)
	actx := checkmk.GatherContext(ctx, cfg, alert, hostInfo)
	alertContext := actx.FormatForPrompt()

	sshOK := cfg.SSHEnabled && validationErr == nil
	if cfg.SSHEnabled && !sshOK {
		alertContext += "\n## Note\nSSH diagnostics unavailable: " + validationErr.Error() + "\n"
	}

	var analysis string

	if sshOK {
		var err error
		analysis, err = checkmk.RunAgenticDiagnostics(ctx, cfg, claudeClient, hostAddress, alertContext, cfg.MaxAgentRounds)
		if err != nil {
			slog.Error("agentic diagnostics failed", "error", err)
			_ = shared.PublishAll(ctx, publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Agentic diagnostics failed** for %s: %v\n\nManual investigation needed.", alert.Title, err))
			cooldownMgr.Clear(alert.Fingerprint)
			metrics.AlertsFailed.Add(1)
			return
		}
	} else {
		var err error
		analysis, err = claudeClient.Analyze(ctx, checkmk.AgentSystemPrompt, alertContext)
		if err != nil {
			slog.Error("analysis failed", "error", err)
			_ = shared.PublishAll(ctx, publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alert.Title, err))
			cooldownMgr.Clear(alert.Fingerprint)
			metrics.AlertsFailed.Add(1)
			return
		}
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "unknown": "3", "ok": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	title := fmt.Sprintf("Analysis: %s", alert.Title)
	if err := shared.PublishAll(ctx, publishers, title, priority, analysis); err != nil {
		cooldownMgr.Clear(alert.Fingerprint)
		metrics.AlertsFailed.Add(1)
		return
	}

	metrics.AlertsProcessed.Add(1)
	slog.Info("analysis complete", "hostname", hostname, "model", cfg.ClaudeModel)
}

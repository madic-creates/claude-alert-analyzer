package shared

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
)

// ServerConfig holds settings for the shared HTTP server and worker pool.
type ServerConfig struct {
	Port         string
	MetricsPort  string
	WorkerCount  int
	QueueSize    int
	DrainTimeout time.Duration
	// ShutdownTimeout is the maximum time allowed for graceful HTTP server
	// shutdown before active connections are abandoned and an error is logged.
	// Defaults to 30 seconds if zero. Tune this down in environments with tight
	// termination grace periods (e.g. Kubernetes SIGTERM → SIGKILL windows).
	ShutdownTimeout time.Duration
	// Source is the analyzer source label used for Prometheus metrics (e.g. "k8s", "checkmk").
	Source string
}

// Server manages a webhook-driven worker pool with graceful shutdown.
type Server struct {
	cfg     ServerConfig
	metrics *AlertMetrics
	process func(ctx context.Context, alert AlertPayload)
	queue   chan AlertPayload
	mu      sync.Mutex // protects stopped and queue close
	stopped bool
}

// NewServer creates a Server. Call Enqueue to add alerts, Run to start.
func NewServer(cfg ServerConfig, metrics *AlertMetrics, process func(ctx context.Context, alert AlertPayload)) *Server {
	return &Server{
		cfg:     cfg,
		metrics: metrics,
		process: process,
		queue:   make(chan AlertPayload, cfg.QueueSize),
	}
}

// Enqueue attempts to place an alert on the work queue.
// Returns false if the queue is full or the server is shutting down.
func (s *Server) Enqueue(alert AlertPayload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	select {
	case s.queue <- alert:
		s.metrics.AlertsQueued.Add(1)
		s.metrics.SetQueueDepth(s.cfg.Source, float64(len(s.queue)))
		return true
	default:
		s.metrics.AlertsQueueFull.Add(1)
		return false
	}
}

// BuildMux returns an http.ServeMux with /health and POST /webhook.
// The webhookHandler is wrapped to increment WebhooksReceived.
// /metrics is served on a separate port via BuildMetricsMux.
func (s *Server) BuildMux(webhookHandler http.HandlerFunc) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.WebhooksReceived.Add(1)
		webhookHandler(w, r)
	})
	return mux
}

// BuildMetricsMux returns an http.ServeMux with only the /metrics endpoint.
func (s *Server) BuildMetricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", s.metrics.MetricsHandler())
	return mux
}

// safeProcess calls s.process and recovers from any panic so the worker
// goroutine stays alive and continues processing subsequent alerts.
func (s *Server) safeProcess(ctx context.Context, alert AlertPayload) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("worker panic recovered",
				"recover", r,
				"fingerprint", alert.Fingerprint,
				"stack", string(debug.Stack()))
		}
	}()
	s.process(ctx, alert)
}

// Run starts workers, serves HTTP, and blocks until SIGINT/SIGTERM triggers
// graceful shutdown. This function does not return until shutdown is complete.
// The main server (PORT) serves /health and /webhook.
// A separate metrics server (METRICS_PORT) serves /metrics.
func (s *Server) Run(webhookHandler http.HandlerFunc) {
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	var wg sync.WaitGroup
	for range s.cfg.WorkerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for alert := range s.queue {
				s.metrics.SetQueueDepth(s.cfg.Source, float64(len(s.queue)))
				s.safeProcess(workerCtx, alert)
			}
		}()
	}

	mux := s.BuildMux(webhookHandler)

	server := &http.Server{
		Addr:              ":" + s.cfg.Port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	metricsPort := s.cfg.MetricsPort
	if metricsPort == "" {
		metricsPort = "9101"
	}
	metricsServer := &http.Server{
		Addr:              ":" + metricsPort,
		Handler:           s.BuildMetricsMux(),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("metrics server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")
	shutdownTimeout := s.cfg.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = 30 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	// Shut down both servers concurrently so each gets the full 30-second
	// budget. Sequential shutdown would give the metrics server whatever time
	// remained after the main server finished, which could be near zero if
	// the main server was draining long-running connections.
	var shutdownWg sync.WaitGroup
	shutdownWg.Add(2)
	go func() {
		defer shutdownWg.Done()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}
	}()
	go func() {
		defer shutdownWg.Done()
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("metrics server shutdown error", "error", err)
		}
	}()
	shutdownWg.Wait()

	s.mu.Lock()
	s.stopped = true
	close(s.queue)
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	// Use time.NewTimer instead of time.After so we can Stop() it when
	// workers finish before the timeout. time.After leaks the underlying
	// timer until it fires; with a 25-second DrainTimeout the leaked timer
	// would remain alive after a clean shutdown where workers drain quickly.
	drainTimeout := s.cfg.DrainTimeout
	if drainTimeout == 0 {
		drainTimeout = 25 * time.Second
	}
	drainTimer := time.NewTimer(drainTimeout)
	defer drainTimer.Stop()
	select {
	case <-done:
		slog.Info("all workers finished")
	case <-drainTimer.C:
		slog.Warn("worker drain timeout, cancelling")
		workerCancel()
		wg.Wait()
	}
	slog.Info("shutdown complete")
}

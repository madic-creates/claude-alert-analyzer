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

	"github.com/prometheus/client_golang/prometheus/promhttp"
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
}

// queuedAlert pairs an alert with the time it was placed on the queue so the
// worker can observe how long the alert waited before processing began.
type queuedAlert struct {
	alert      AlertPayload
	enqueuedAt time.Time
}

// Server manages a webhook-driven worker pool with graceful shutdown.
type Server struct {
	cfg     ServerConfig
	metrics *AlertMetrics
	process func(ctx context.Context, alert AlertPayload)
	queue   chan queuedAlert
	mu      sync.Mutex // protects stopped and queue close
	stopped bool
}

// NewServer creates a Server. Call Enqueue to add alerts, Run to start.
func NewServer(cfg ServerConfig, metrics *AlertMetrics, process func(ctx context.Context, alert AlertPayload)) *Server {
	return &Server{
		cfg:     cfg,
		metrics: metrics,
		process: process,
		queue:   make(chan queuedAlert, cfg.QueueSize),
	}
}

// Enqueue attempts to place an alert on the work queue. Returns false if the
// queue is full or the server is shutting down.
//
// Counter ownership: handlers own RecordEnqueued/RecordDropped — Enqueue only
// updates QueueDepth (the queue state).
func (s *Server) Enqueue(alert AlertPayload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	select {
	case s.queue <- queuedAlert{alert: alert, enqueuedAt: time.Now()}:
		s.metrics.SetQueueDepth(float64(len(s.queue)))
		return true
	default:
		return false
	}
}

// BuildMux returns an http.ServeMux with /health and POST /webhook.
// /metrics is served on a separate port via BuildMetricsMux. The webhook
// handler is responsible for emitting RecordWebhookOutcome once per request.
func (s *Server) BuildMux(webhookHandler http.HandlerFunc) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("POST /webhook", webhookHandler)
	return mux
}

// BuildMetricsMux returns an http.ServeMux with only the /metrics endpoint.
// When metrics or its Prom field is nil, returns a 200 with empty body so
// callers (and tests) get a stable response shape.
func (s *Server) BuildMetricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	if s.metrics == nil || s.metrics.Prom == nil {
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			w.WriteHeader(http.StatusOK)
		})
		return mux
	}
	mux.Handle("GET /metrics", promhttp.HandlerFor(
		s.metrics.Prom.Registry(),
		promhttp.HandlerOpts{DisableCompression: true},
	))
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
			for qa := range s.queue {
				s.metrics.SetQueueDepth(float64(len(s.queue)))
				s.metrics.ObserveQueueWaitDuration(time.Since(qa.enqueuedAt))
				s.safeProcess(workerCtx, qa.alert)
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
		// Bias toward done: when workers finish at the same instant the
		// drain timer fires, Go's select picks at random. Without this
		// non-blocking re-check, a clean shutdown can emit a misleading
		// "drain timeout, cancelling" log line and invoke workerCancel()
		// even though all workers actually completed in time. Mirrors the
		// pattern at NotifyAggregator's drain loop (notify_aggregator.go),
		// runSSHCommand (internal/checkmk/ssh.go), and Publish's retry
		// select (internal/shared/ntfy.go).
		if testHookBeforeServerDrainRecheck != nil {
			testHookBeforeServerDrainRecheck()
		}
		select {
		case <-done:
			slog.Info("all workers finished")
		default:
			slog.Warn("worker drain timeout, cancelling")
			workerCancel()
			wg.Wait()
		}
	}
	slog.Info("shutdown complete")
}

// testHookBeforeServerDrainRecheck is called by Run() in tests after the
// drain-timer select picks the timer branch but before the post-select
// re-check of done. It lets tests stage the "done and drainTimer.C ready at
// the same instant" race that the bias guard above defeats. Nil in
// production.
var testHookBeforeServerDrainRecheck func()

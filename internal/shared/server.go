package shared

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ServerConfig holds settings for the shared HTTP server and worker pool.
type ServerConfig struct {
	Port         string
	WorkerCount  int
	QueueSize    int
	DrainTimeout time.Duration
}

// Server manages a webhook-driven worker pool with graceful shutdown.
type Server struct {
	cfg     ServerConfig
	metrics *AlertMetrics
	process func(ctx context.Context, alert AlertPayload)
	queue   chan AlertPayload
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
// Returns false if the queue is full.
func (s *Server) Enqueue(alert AlertPayload) bool {
	select {
	case s.queue <- alert:
		s.metrics.AlertsQueued.Add(1)
		return true
	default:
		s.metrics.AlertsQueueFull.Add(1)
		return false
	}
}

// BuildMux returns an http.ServeMux with /health, /metrics, and POST /webhook.
// The webhookHandler is wrapped to increment WebhooksReceived.
func (s *Server) BuildMux(webhookHandler http.HandlerFunc) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("GET /metrics", s.metrics.MetricsHandler())
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.WebhooksReceived.Add(1)
		webhookHandler(w, r)
	})
	return mux
}

// Run starts workers, serves HTTP, and blocks until SIGINT/SIGTERM triggers
// graceful shutdown. This function does not return until shutdown is complete.
func (s *Server) Run(webhookHandler http.HandlerFunc) {
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	var wg sync.WaitGroup
	for range s.cfg.WorkerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for alert := range s.queue {
				s.process(workerCtx, alert)
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx) //nolint:errcheck

	close(s.queue)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("all workers finished")
	case <-time.After(s.cfg.DrainTimeout):
		slog.Warn("worker drain timeout, cancelling")
		workerCancel()
		wg.Wait()
	}
	slog.Info("shutdown complete")
}

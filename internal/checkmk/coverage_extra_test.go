package checkmk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"golang.org/x/crypto/ssh"
)

// TestValidateAndDescribeHost_NoIPConfigured verifies that when the CheckMK API
// returns a valid host response but the ipaddress attribute is empty, the function
// returns both a non-nil HostInfo (populated with whatever other fields the API
// provided) and a descriptive error explaining that no IP is configured.
// This branch (context.go lines 141-143) was previously untested.
func TestValidateAndDescribeHost_NoIPConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a valid host response with an empty ipaddress field.
		resp := checkmkHostResponse{
			ID: "noiphost",
			Extensions: checkmkHostExtensions{
				Attributes: checkmkHostAttributes{
					IPAddress: "", // deliberately empty
					AIContext: "Some context",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	info, err := apiClient.ValidateAndDescribeHost(context.Background(), "noiphost", "10.0.0.1")

	if err == nil {
		t.Fatal("expected error for host with no IP configured, got nil")
	}
	if !strings.Contains(err.Error(), "no IP address configured") {
		t.Errorf("error should mention 'no IP address configured', got: %v", err)
	}
	// The HostInfo must still be returned so callers can access any other fields
	// (e.g. AIContext) even though IP validation failed.
	if info == nil {
		t.Fatal("HostInfo must not be nil even when IP is missing")
	}
	if info.AIContext != "Some context" {
		t.Errorf("AIContext = %q, want %q", info.AIContext, "Some context")
	}
}

// TestGetHostServices_RequestCreateError verifies that GetHostServices returns a
// descriptive error string when http.NewRequestWithContext fails. In practice this
// path is triggered by an invalid URL in the APIClient. The branch at
// context.go:159 ("(request error: ...)") was previously uncovered.
func TestGetHostServices_RequestCreateError(t *testing.T) {
	// A URL with a control character in it causes NewRequestWithContext to fail.
	apiClient := &APIClient{
		HTTP:   http.DefaultClient,
		URL:    "http://host\x00invalid/api/",
		User:   "auto",
		Secret: "secret",
	}
	result := apiClient.GetHostServices(context.Background(), "host1")
	if !strings.Contains(result, "request error") {
		t.Errorf("expected '(request error: ...)' for invalid URL, got: %s", result)
	}
}

// TestGetHostServices_APIRequestFails verifies the "(CheckMK API failed: ...)"
// sentinel returned when the HTTP Do call itself fails (e.g. the server is down).
// This is distinct from a non-200 HTTP status: here the TCP dial itself fails.
func TestGetHostServices_APIRequestFails(t *testing.T) {
	// Port 1 is almost always closed, so the request will fail at the TCP level.
	apiClient := &APIClient{
		HTTP:   &http.Client{},
		URL:    "http://127.0.0.1:1/",
		User:   "auto",
		Secret: "secret",
	}
	result := apiClient.GetHostServices(context.Background(), "host1")
	if !strings.Contains(result, "CheckMK API failed") {
		t.Errorf("expected '(CheckMK API failed: ...)' for unreachable server, got: %s", result)
	}
}

// TestSSHDialer_Dial_HandshakeFailure verifies that SSHDialer.Dial returns a
// descriptive error when the TCP connection succeeds but the SSH handshake fails.
// This covers lines 72-77 of ssh.go (the "SSH handshake with ..." error path).
// SSHDialer.Dial hardcodes port 22, so we must listen on port 22. If port 22 is
// already in use (e.g. a real sshd), the test is skipped.
func TestSSHDialer_Dial_HandshakeFailure(t *testing.T) {
	// SSHDialer.Dial always dials ip:22.
	ln, err := net.Listen("tcp", "127.0.0.1:22")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1:22 (already in use or no permission): %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() // close immediately — SSH handshake cannot complete
		}
	}()

	d, err := buildTestDialer(t)
	if err != nil {
		t.Fatalf("buildTestDialer: %v", err)
	}

	// Dial("localhost", "127.0.0.1") will connect to 127.0.0.1:22 where the
	// server immediately closes the connection, triggering the handshake error.
	_, dialErr := d.Dial("localhost", "127.0.0.1")
	if dialErr == nil {
		t.Fatal("expected SSH handshake error, got nil")
	}
	if !strings.Contains(dialErr.Error(), "SSH handshake") {
		t.Errorf("expected 'SSH handshake' in error message, got: %v", dialErr)
	}
}

// TestSSHDialer_Dial_HappyPath verifies that SSHDialer.Dial returns a live
// *ssh.Client when both the TCP connection and SSH handshake succeed.
// SSHDialer.Dial hardcodes port 22; the test is skipped if port 22 is unavailable.
func TestSSHDialer_Dial_HappyPath(t *testing.T) {
	// Build a real in-process SSH server listening on port 22.
	ln, err := net.Listen("tcp", "127.0.0.1:22")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1:22: %v", err)
	}

	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		ln.Close()
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		ln.Close()
		t.Fatalf("host signer: %v", err)
	}
	hostPubKey, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		ln.Close()
		t.Fatalf("host pub key: %v", err)
	}

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		ln.Close()
		t.Fatalf("generate client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		ln.Close()
		t.Fatalf("client signer: %v", err)
	}

	serverCfg := &ssh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(hostSigner)

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srvConn, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
		if err != nil {
			return
		}
		defer srvConn.Close()
		go ssh.DiscardRequests(reqs)
		for newChan := range chans {
			_ = newChan.Reject(ssh.UnknownChannelType, "not needed")
		}
	}()

	d := &SSHDialer{
		user:            "test",
		signer:          clientSigner,
		hostKeyCallback: ssh.FixedHostKey(hostPubKey),
	}

	client, dialErr := d.Dial("localhost", "127.0.0.1")
	if dialErr != nil {
		t.Fatalf("Dial returned unexpected error: %v", dialErr)
	}
	if client == nil {
		t.Fatal("Dial returned nil client on success")
	}
	client.Close()
}

// buildTestDialer creates an SSHDialer suitable for unit tests. It uses
// ephemeral ed25519 keys and an InsecureIgnoreHostKey callback so tests can
// connect to servers whose host keys are not pre-registered in a known_hosts file.
func buildTestDialer(t *testing.T) (*SSHDialer, error) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}
	return &SSHDialer{
		user:            "test",
		signer:          signer,
		hostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — test only
	}, nil
}

// TestProcessAlert_AnalysisFails_PublishFailureNotification verifies that when
// analysis fails, a failure notification is published to ntfy AND if that
// secondary publish also fails, the pipeline logs a warning but still returns
// (the slog.Warn path at pipeline.go lines 77-78 and 91-92).
func TestProcessAlert_AnalysisFails_PublishFailureNotification(t *testing.T) {
	failPub := &mockPublisher{err: fmt.Errorf("ntfy unreachable")}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{err: fmt.Errorf("claude timeout")},
		Publishers: []shared.Publisher{failPub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fail-pub-fp",
		Title:       "Test",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "h", "host_address": "1.2.3.4"},
	}

	// Must not panic even when both analysis and the failure-notification publish fail.
	ProcessAlert(context.Background(), deps, alert)

	// The primary failure (analysis error) must still be counted.
	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
	// publish was attempted (for the failure notification) even though it failed.
	if len(failPub.calls) != 1 {
		t.Errorf("expected 1 publish call (failure notification), got %d", len(failPub.calls))
	}
}

// TestProcessAlert_EmptyAnalysis_PublishFailureNotification verifies the publish
// failure path inside the empty-analysis branch of ProcessAlert. When the
// empty-result failure notification publish fails, the pipeline must still
// decrement correctly and not panic.
func TestProcessAlert_EmptyAnalysis_PublishFailureNotification(t *testing.T) {
	failPub := &mockPublisher{err: fmt.Errorf("ntfy down")}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "", err: nil},
		Publishers: []shared.Publisher{failPub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "empty-fail-pub",
		Title:       "EmptyTest",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "h", "host_address": "1.2.3.4"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
}

// TestProcessAlert_SSH_AgenticFails_PublishFailureNotification verifies that
// when SSH agentic diagnostics fail (RunToolLoop returns an error) AND the
// failure notification publish also fails, the pipeline logs a warning, still
// increments AlertsFailed, clears the cooldown, and returns without panicking.
// This covers the slog.Warn path at pipeline.go lines 76-77 (SSH agentic branch).
func TestProcessAlert_SSH_AgenticFails_PublishFailureNotification(t *testing.T) {
	sshClient := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		sendExitStatus(ch, 0)
	})
	dialer := &fixedDialer{client: sshClient}
	failPub := &mockPublisher{err: fmt.Errorf("ntfy unreachable")}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		ToolRunner: &capturingToolRunner{err: fmt.Errorf("tool loop failed")},
		Publishers: []shared.Publisher{failPub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: true,
		SSHDialer:  dialer,
		SSHConfig:  Config{MaxAgentRounds: 3, SSHDeniedCommands: DefaultDeniedCommands},
		GatherContext: func(_ context.Context, _ shared.AlertPayload, _ *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(_ context.Context, _, _ string) (*HostInfo, error) {
			return &HostInfo{VerifiedIP: "10.0.0.1"}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "ssh-agentic-fail-pub-fp",
		Title:       "host1 - High Load",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "host1", "host_address": "10.0.0.1"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
	if metrics.AlertsProcessed.Load() != 0 {
		t.Errorf("AlertsProcessed = %d, want 0", metrics.AlertsProcessed.Load())
	}
	if len(failPub.calls) != 1 {
		t.Errorf("expected 1 publish call (failure notification), got %d", len(failPub.calls))
	}
	// Cooldown must be cleared so the next webhook triggers a retry.
	if !cooldown.CheckAndSet("ssh-agentic-fail-pub-fp", 300*time.Second) {
		t.Error("cooldown not cleared after SSH agentic failure")
	}
}

// TestHandleWebhook_BodyReadError verifies that when the request body read fails
// for a reason other than being too large (e.g. a closed connection), the handler
// returns 400 Bad Request. This covers the "bad request" branch at handler.go:42.
func TestHandleWebhook_BodyReadError(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil)

	// Use an errorReader that returns an error immediately on Read.
	req := httptest.NewRequest("POST", "/webhook", &errorReader{})
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for body read error, got %d", rr.Code)
	}
}

// errorReader implements io.Reader and always returns an error that is NOT
// *http.MaxBytesError, triggering the generic "bad request" branch.
type errorReader struct{}

func (e *errorReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated read failure")
}

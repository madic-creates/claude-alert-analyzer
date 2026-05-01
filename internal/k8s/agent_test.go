package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

func TestParseKubectlInput_BasicValidation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "empty argv",
			input:   `{"command":[]}`,
			wantErr: "empty command",
		},
		{
			name:    "argv too long",
			input:   `{"command":[` + strings.Repeat(`"x",`, 64) + `"x"]}`,
			wantErr: "maximum is 64",
		},
		{
			name:    "single arg too long",
			input:   `{"command":["` + strings.Repeat("x", 4097) + `"]}`,
			wantErr: "maximum length",
		},
		{
			name:    "total bytes too long",
			input:   `{"command":[` + strings.Repeat(`"`+strings.Repeat("x", 4096)+`",`, 4) + `"x"]}`,
			wantErr: "exceeds maximum",
		},
		{
			name:    "empty arg",
			input:   `{"command":["get",""]}`,
			wantErr: "is empty",
		},
		{
			name:    "whitespace-only arg",
			input:   `{"command":["get","   "]}`,
			wantErr: "whitespace-only",
		},
		{
			name:    "leading whitespace",
			input:   `{"command":["get"," pods"]}`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "trailing whitespace",
			input:   `{"command":["get","pods "]}`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "newline in arg",
			input:   `{"command":["get","pods\nfoo"]}`,
			wantErr: "control character",
		},
		{
			name:    "tab in arg",
			input:   `{"command":["get","pods\tfoo"]}`,
			wantErr: "control character",
		},
		{
			// U+0080 is a C1 control character. It is a valid Unicode code point
			// that JSON decodes transparently. The Go \u0080 escape is resolved to
			// rune U+0080 at compile time; json.Marshal encodes it as "\u0080" in
			// the JSON output, which json.Unmarshal decodes back to the same rune.
			name:    "C1 control char (U+0080)",
			input:   string(mustMarshalCommand([]string{"get", "pods\u0080"})),
			wantErr: "control character",
		},
		{
			name:    "DEL (0x7f)",
			input:   string(mustMarshalCommand([]string{"get", "pods\x7f"})),
			wantErr: "control character",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseKubectlInput(json.RawMessage(tc.input))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestParseKubectlInput_ValidArgv(t *testing.T) {
	got, err := parseKubectlInput(json.RawMessage(`{"command":["get","pods","-n","monitoring"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"get", "pods", "-n", "monitoring"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// mustMarshalCommand serializes a kubectl command array to JSON for test
// inputs that require literal control characters that cannot be expressed as
// JSON string escapes in a Go raw-string literal.
func mustMarshalCommand(argv []string) []byte {
	b, err := json.Marshal(struct {
		Command []string `json:"command"`
	}{Command: argv})
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseKubectlInput_VerbAllowlist(t *testing.T) {
	allowed := []string{
		`["get","pods"]`,
		`["describe","pod","prom-0"]`,
		`["logs","prom-0","--tail=20"]`,
		`["top","nodes"]`,
		`["events","-n","monitoring"]`,
		`["explain","pods.spec.containers"]`,
		`["version","--short"]`,
		`["api-resources"]`,
		`["api-versions"]`,
		`["cluster-info"]`,
		`["auth","can-i","get","pods"]`,
		`["rollout","history","deployment/foo"]`,
		// flags before verb are tolerated as long as the FIRST non-flag is a verb
		`["-v=4","get","pods"]`,
	}
	for _, c := range allowed {
		t.Run("allowed:"+c, func(t *testing.T) {
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + c + `}`))
			if err != nil {
				t.Errorf("expected no error for %s, got %v", c, err)
			}
		})
	}

	rejected := []struct {
		argv    string
		wantErr string
	}{
		{`["delete","pod","prom-0"]`, "delete"},
		{`["apply","-f","x.yaml"]`, "apply"},
		{`["create","ns","x"]`, "create"},
		{`["edit","pod","prom-0"]`, "edit"},
		{`["patch","pod","prom-0","-p","{}"]`, "patch"},
		{`["replace","-f","x.yaml"]`, "replace"},
		{`["scale","--replicas=0","deployment/foo"]`, "scale"},
		{`["cordon","node-1"]`, "cordon"},
		{`["drain","node-1"]`, "drain"},
		{`["uncordon","node-1"]`, "uncordon"},
		{`["exec","prom-0","--","sh"]`, "exec"},
		{`["cp","prom-0:/tmp/x","./x"]`, "cp"},
		{`["port-forward","prom-0","9090"]`, "port-forward"},
		{`["proxy"]`, "proxy"},
		{`["debug","prom-0"]`, "debug"},
		{`["attach","prom-0"]`, "attach"},
		{`["wait","--for=condition=Ready","pod/prom-0"]`, "wait"},
		{`["config","view"]`, "config"},
		{`["kustomize","./manifests"]`, "kustomize"},
		{`["plugin","list"]`, "plugin"},
		{`["completion","bash"]`, "completion"},
		{`["alpha","debug","node-1"]`, "alpha"},
		{`["kubectl-foo","args"]`, "kubectl-foo"},
		// auth sub-verb rules
		{`["auth","whoami"]`, "auth whoami"},
		{`["auth","reconcile"]`, "auth reconcile"},
		// rollout sub-verb rules
		{`["rollout","status","deployment/foo"]`, "rollout status"},
		{`["rollout","restart","deployment/foo"]`, "rollout restart"},
		{`["rollout","undo","deployment/foo"]`, "rollout undo"},
	}
	for _, c := range rejected {
		t.Run("rejected:"+c.argv, func(t *testing.T) {
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + c.argv + `}`))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("expected error containing %q, got %q", c.wantErr, err.Error())
			}
		})
	}
}

func TestParseKubectlInput_GlobalFlagDenylist(t *testing.T) {
	deniedFlags := []string{
		"--kubeconfig", "--server", "--token", "--token-file",
		"--as", "--as-group", "--as-uid",
		"--user", "--cluster", "--context",
		"--certificate-authority",
		"--client-certificate", "--client-key",
		"--insecure-skip-tls-verify",
		"--password", "--username",
		"--tls-server-name",
		"--cache-dir",
	}
	for _, f := range deniedFlags {
		// --flag value form
		t.Run("space:"+f, func(t *testing.T) {
			argv := `["get","pods","` + f + `","value"]`
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + argv + `}`))
			if err == nil || !strings.Contains(err.Error(), f) {
				t.Errorf("expected rejection naming %q, got %v", f, err)
			}
		})
		// --flag=value form
		t.Run("equals:"+f, func(t *testing.T) {
			argv := `["get","pods","` + f + `=value"]`
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + argv + `}`))
			if err == nil || !strings.Contains(err.Error(), f) {
				t.Errorf("expected rejection naming %q, got %v", f, err)
			}
		})
		// flag before verb form
		t.Run("before-verb:"+f, func(t *testing.T) {
			argv := `["` + f + `=value","get","pods"]`
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + argv + `}`))
			if err == nil || !strings.Contains(err.Error(), f) {
				t.Errorf("expected rejection naming %q, got %v", f, err)
			}
		})
	}

	t.Run("short -s flag", func(t *testing.T) {
		_, err := parseKubectlInput(json.RawMessage(`{"command":["get","pods","-s","https://attacker"]}`))
		if err == nil || !strings.Contains(err.Error(), "-s") {
			t.Errorf("expected rejection naming -s, got %v", err)
		}
	})
	t.Run("short -s does not match longer flags", func(t *testing.T) {
		// Make sure substring matching does NOT happen — argv element "--since"
		// must not be rejected as if it were "-s".
		_, err := parseKubectlInput(json.RawMessage(`{"command":["logs","prom-0","--since=10m"]}`))
		if err != nil {
			t.Errorf("expected no rejection for --since, got %v", err)
		}
	})
	t.Run("short -s with equals form", func(t *testing.T) {
		_, err := parseKubectlInput(json.RawMessage(`{"command":["get","pods","-s=https://attacker.com"]}`))
		if err == nil || !strings.Contains(err.Error(), "-s") {
			t.Errorf("expected rejection naming -s, got %v", err)
		}
	})
	t.Run("short -s attached form", func(t *testing.T) {
		_, err := parseKubectlInput(json.RawMessage(`{"command":["get","pods","-shttps://attacker.com"]}`))
		if err == nil || !strings.Contains(err.Error(), "-s") {
			t.Errorf("expected rejection naming -s, got %v", err)
		}
	})
}

func TestAgentSystemPromptForRounds(t *testing.T) {
	got := agentSystemPromptForRounds(7)
	if !strings.Contains(got, "maximum of 7 tool rounds") {
		t.Errorf("expected '7 tool rounds' in output, got:\n%s", got)
	}
	if !strings.Contains(got, "kubectl_exec") {
		t.Errorf("expected kubectl_exec mention in prompt")
	}
	if !strings.Contains(got, "promql_query") {
		t.Errorf("expected promql_query mention in prompt")
	}
}

func TestKubectlTool_Definition(t *testing.T) {
	if kubectlTool.Name != "kubectl_exec" {
		t.Errorf("kubectlTool.Name = %q, want kubectl_exec", kubectlTool.Name)
	}
	if _, ok := kubectlTool.InputSchema.Properties["command"]; !ok {
		t.Error("kubectlTool.InputSchema missing 'command' property")
	}
}

func TestPromqlTool_Definition(t *testing.T) {
	if promqlTool.Name != "promql_query" {
		t.Errorf("promqlTool.Name = %q, want promql_query", promqlTool.Name)
	}
	if _, ok := promqlTool.InputSchema.Properties["query"]; !ok {
		t.Error("promqlTool.InputSchema missing 'query' property")
	}
}

// TestHelperProcess plays the role of the kubectl child process when the
// test binary is invoked with GO_KUBECTL_HELPER=1. It reflects argv and
// selected env back to stdout/stderr so the parent test can assert on them.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_KUBECTL_HELPER") != "1" {
		return
	}
	// argv: print everything after "--" so we can include go-test's own args
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	fmt.Printf("ARGV: %v\n", args)

	// env: print sorted, but skip Go test machinery and PWD so the assertion
	// can match the user-visible env exactly
	env := os.Environ()
	sort.Strings(env)
	for _, e := range env {
		if strings.HasPrefix(e, "GO_") || strings.HasPrefix(e, "PWD=") {
			continue
		}
		fmt.Printf("ENV: %s\n", e)
	}

	switch os.Getenv("HELPER_MODE") {
	case "fail":
		fmt.Fprintln(os.Stderr, "stderr line")
		os.Exit(2)
	case "sleep":
		time.Sleep(2 * time.Second)
	}
	os.Exit(0)
}

func helperPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

func TestKubectlSubprocess_ArgvAndEnv(t *testing.T) {
	t.Setenv("HOME", "/tmp")
	t.Setenv("USER", "tester")
	t.Setenv("KUBECONFIG", "/should/not/leak")

	runner := &kubectlSubprocess{
		Path: helperPath(t),
		Env:  []string{"HOME=/tmp", "USER=tester", "GO_KUBECTL_HELPER=1"},
	}
	out, err := runner.Exec(context.Background(),
		[]string{"-test.run=TestHelperProcess", "--", "get", "pods"},
		5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "ARGV: [get pods]") {
		t.Errorf("argv pass-through failed; output:\n%s", out)
	}
	if strings.Contains(out, "KUBECONFIG=") {
		t.Errorf("KUBECONFIG should not have leaked; output:\n%s", out)
	}
	if !strings.Contains(out, "ENV: HOME=/tmp") {
		t.Errorf("HOME not present; output:\n%s", out)
	}
	if !strings.Contains(out, "ENV: USER=tester") {
		t.Errorf("USER not present; output:\n%s", out)
	}
}

func TestKubectlSubprocess_NonZeroExitWithOutput(t *testing.T) {
	runner := &kubectlSubprocess{
		Path: helperPath(t),
		Env:  []string{"HOME=/tmp", "USER=tester", "GO_KUBECTL_HELPER=1", "HELPER_MODE=fail"},
	}
	out, err := runner.Exec(context.Background(),
		[]string{"-test.run=TestHelperProcess", "--", "get", "pods"},
		5*time.Second)
	if err == nil {
		t.Fatalf("expected non-zero exit error, got nil; output:\n%s", out)
	}
	if !strings.Contains(out, "stderr line") {
		t.Errorf("expected combined stdout+stderr capture; output:\n%s", out)
	}
}

func TestKubectlSubprocess_Timeout(t *testing.T) {
	runner := &kubectlSubprocess{
		Path: helperPath(t),
		Env:  []string{"HOME=/tmp", "USER=tester", "GO_KUBECTL_HELPER=1", "HELPER_MODE=sleep"},
	}
	start := time.Now()
	_, err := runner.Exec(context.Background(),
		[]string{"-test.run=TestHelperProcess", "--", "get", "pods"},
		200*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Errorf("timeout did not fire promptly: %v", time.Since(start))
	}
}

func TestKubectlSubprocess_MissingBinary(t *testing.T) {
	runner := &kubectlSubprocess{
		Path: "/nonexistent/kubectl",
		Env:  []string{"HOME=/tmp", "USER=tester"},
	}
	_, err := runner.Exec(context.Background(), []string{"get", "pods"}, 5*time.Second)
	if err == nil {
		t.Fatalf("expected ENOENT error, got nil")
	}
}

func TestParsePromQLInput(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{
			name:  "valid query",
			input: `{"query":"up"}`,
			want:  "up",
		},
		{
			name:    "empty query",
			input:   `{"query":""}`,
			wantErr: "empty query",
		},
		{
			name:    "whitespace-only",
			input:   `{"query":"   "}`,
			wantErr: "empty query",
		},
		{
			name:    "newline embedded",
			input:   `{"query":"up\n## injected"}`,
			wantErr: "control character",
		},
		{
			name:    "tab embedded",
			input:   `{"query":"up\tfoo"}`,
			wantErr: "control character",
		},
		{
			name:    "too long",
			input:   `{"query":"` + strings.Repeat("x", 4097) + `"}`,
			wantErr: "exceeds maximum",
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantErr: "parse query input",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePromQLInput(json.RawMessage(tc.input))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// fakeToolLoopRunner is a controllable mock of shared.ToolLoopRunner. The
// caller provides a function that drives the conversation: it receives the
// handleTool callback and can call it any number of times, returning a
// final analysis string + nil error (or an error to simulate API failure).
// It records the userPrompt that was passed in.
type fakeToolLoopRunner struct {
	captured string
	driver   func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error)
}

func (f *fakeToolLoopRunner) RunToolLoop(
	ctx context.Context, model, system, user string,
	tools []shared.Tool, maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error) {
	f.captured = user
	out, err := f.driver(handleTool)
	// Test fakes: return placeholder rounds=1, exhausted=false. Tests asserting
	// on these values can use a different fake.
	return out, 1, false, err
}

type fakeKubectlRunner struct {
	calls    [][]string
	response string
	err      error
}

func (f *fakeKubectlRunner) Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error) {
	f.calls = append(f.calls, append([]string(nil), argv...))
	return f.response, f.err
}

type fakePromQLQuerier struct {
	calls    []string
	response string
}

func (f *fakePromQLQuerier) Query(ctx context.Context, q string) string {
	f.calls = append(f.calls, q)
	return f.response
}

func TestRunAgenticDiagnostics_HappyPath(t *testing.T) {
	kc := &fakeKubectlRunner{response: "pod-x   Running\n"}
	pq := &fakePromQLQuerier{response: "up: 1"}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("kubectl_exec", json.RawMessage(`{"command":["get","pods"]}`))
			if err != nil {
				t.Fatalf("handleTool unexpected error: %v", err)
			}
			if !strings.Contains(out, "pod-x") {
				t.Errorf("expected kubectl output, got %q", out)
			}
			return "## Root cause\nfinal analysis", nil
		},
	}

	got, err := RunAgenticDiagnostics(
		context.Background(), runner, kc, pq, metrics,
		"## Alert: Foo\nbody", 10, "test-model",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "Root cause") {
		t.Errorf("unexpected analysis: %q", got)
	}
	if runner.captured != "## Alert: Foo\nbody" {
		t.Errorf("user prompt not preserved verbatim: %q", runner.captured)
	}
	if len(kc.calls) != 1 || kc.calls[0][0] != "get" {
		t.Errorf("unexpected kubectl calls: %v", kc.calls)
	}
}

func TestRunAgenticDiagnostics_PromQLDispatch(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{response: "up: 1"}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("promql_query", json.RawMessage(`{"query":"up"}`))
			if err != nil {
				t.Fatalf("handleTool: %v", err)
			}
			if !strings.Contains(out, "up: 1") {
				t.Errorf("expected promql result, got %q", out)
			}
			return "ok", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10, "test-model"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pq.calls) != 1 || pq.calls[0] != "up" {
		t.Errorf("unexpected promql calls: %v", pq.calls)
	}
}

func TestRunAgenticDiagnostics_ValidationRejected(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("kubectl_exec", json.RawMessage(`{"command":["delete","pod","x"]}`))
			if err != nil {
				t.Fatalf("validation rejection should not return Go error, got: %v", err)
			}
			if !strings.Contains(out, "command denied") {
				t.Errorf("expected denial string, got: %q", out)
			}
			if len(kc.calls) != 0 {
				t.Errorf("kubectl runner should not have been called for denied verb")
			}
			return "stopped early", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10, "test-model"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAgenticDiagnostics_UnknownTool(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			_, err := handleTool("not_a_tool", json.RawMessage(`{}`))
			if err == nil {
				t.Fatalf("expected error for unknown tool, got nil")
			}
			return "ok", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10, "test-model"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAgenticDiagnostics_RecordsMetrics(t *testing.T) {
	kc := &fakeKubectlRunner{response: "ok\n"}
	pq := &fakePromQLQuerier{response: "v"}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			_, _ = handleTool("kubectl_exec", json.RawMessage(`{"command":["get","pods"]}`))
			_, _ = handleTool("kubectl_exec", json.RawMessage(`{"command":["delete","pod","x"]}`))
			_, _ = handleTool("promql_query", json.RawMessage(`{"query":"up"}`))
			return "done", nil
		},
	}
	_, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10, "test-model")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	metrics.MetricsHandler()(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `agent_tool_calls_total{outcome="ok",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing kubectl ok counter; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_calls_total{outcome="rejected_verb",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing kubectl rejected_verb counter; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_calls_total{outcome="ok",source="k8s",tool="promql_query"} 1`) {
		t.Errorf("missing promql ok counter; body:\n%s", body)
	}
}

type panickyKubectlRunner struct{}

func (panickyKubectlRunner) Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error) {
	panic("synthetic panic for test")
}

func TestRunAgenticDiagnostics_PanicRecovery(t *testing.T) {
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	loopReturned := false
	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			result, err := handleTool("kubectl_exec", json.RawMessage(`{"command":["get","pods"]}`))
			if err != nil {
				t.Errorf("safeHandleTool should swallow panic to nil error, got: %v", err)
			}
			if !strings.Contains(result, "panicked") {
				t.Errorf("expected panic-recovery message in result, got: %q", result)
			}
			// Loop continues after panic and reaches return
			loopReturned = true
			return "analysis after panic", nil
		},
	}

	out, err := RunAgenticDiagnostics(
		context.Background(), runner, panickyKubectlRunner{}, pq, metrics,
		"ctx", 10, "test-model",
	)
	if err != nil {
		t.Fatalf("loop should not return error after recovered panic: %v", err)
	}
	if out != "analysis after panic" {
		t.Errorf("loop did not complete after panic: out=%q", out)
	}
	if !loopReturned {
		t.Error("loop driver did not reach return after panic")
	}

	// Metric assertion: panic recorded as exec_error outcome
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	metrics.MetricsHandler()(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `agent_tool_calls_total{outcome="exec_error",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing exec_error metric for panicked call; body:\n%s", body)
	}
}

// fakeToolLoopRunnerExhausted is a variant that returns rounds=maxRounds, exhausted=true.
type fakeToolLoopRunnerExhausted struct {
	maxRounds int
}

func (f *fakeToolLoopRunnerExhausted) RunToolLoop(
	ctx context.Context, model, system, user string,
	tools []shared.Tool, maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error) {
	return "forced summary text", f.maxRounds, true, nil
}

func TestRunAgenticDiagnostics_ForcedSummary(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}
	runner := &fakeToolLoopRunnerExhausted{maxRounds: 10}

	out, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10, "test-model")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "forced summary text" {
		t.Errorf("expected forced summary text, got %q", out)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	metrics.MetricsHandler()(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `agent_rounds_exhausted_total{source="k8s"} 1`) {
		t.Errorf("expected exhausted counter to fire; body:\n%s", body)
	}
}

func TestRunAgenticDiagnostics_RBACForbidden(t *testing.T) {
	// Simulate kubectl returning a Forbidden error from the API server.
	kc := &fakeKubectlRunner{
		response: `Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:k8s-analyzer" cannot list resource "pods" in API group "" in the namespace "kube-system"`,
		err:      fmt.Errorf("exit status 1"),
	}
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			result, err := handleTool("kubectl_exec", json.RawMessage(`{"command":["get","pods","-n","kube-system"]}`))
			if err != nil {
				t.Errorf("RBAC error should not propagate as Go error to RunToolLoop, got: %v", err)
			}
			if !strings.Contains(result, "Forbidden") {
				t.Errorf("RBAC error message should be visible in tool result, got: %q", result)
			}
			if !strings.Contains(result, "[exited:") {
				t.Errorf("expected exit-code annotation, got: %q", result)
			}
			return "ok", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10, "test-model"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	metrics.MetricsHandler()(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `agent_tool_calls_total{outcome="nonzero_exit",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("expected nonzero_exit metric for RBAC denial; body:\n%s", body)
	}
}

func TestSummarizeKubectlArgv(t *testing.T) {
	cases := []struct {
		name     string
		argv     []string
		wantVerb string
		wantRes  string
		wantNS   string
	}{
		{
			name:     "get pods",
			argv:     []string{"get", "pods"},
			wantVerb: "get", wantRes: "pods",
		},
		{
			name:     "get pods -n monitoring",
			argv:     []string{"get", "pods", "-n", "monitoring"},
			wantVerb: "get", wantRes: "pods", wantNS: "monitoring",
		},
		{
			name:     "logs with --namespace=",
			argv:     []string{"logs", "pod-x", "--namespace=default"},
			wantVerb: "logs", wantRes: "pod-x", wantNS: "default",
		},
		{
			name:     "-n= short form",
			argv:     []string{"describe", "node", "-n=kube-system"},
			wantVerb: "describe", wantRes: "node", wantNS: "kube-system",
		},
		{
			name:     "flags before verb",
			argv:     []string{"-v=4", "get", "events"},
			wantVerb: "get", wantRes: "events",
		},
		{
			name:     "verb only",
			argv:     []string{"cluster-info"},
			wantVerb: "cluster-info",
		},
		{
			name: "empty argv",
			argv: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verb, resource, namespace := summarizeKubectlArgv(tc.argv)
			if verb != tc.wantVerb {
				t.Errorf("verb: got %q, want %q", verb, tc.wantVerb)
			}
			if resource != tc.wantRes {
				t.Errorf("resource: got %q, want %q", resource, tc.wantRes)
			}
			if namespace != tc.wantNS {
				t.Errorf("namespace: got %q, want %q", namespace, tc.wantNS)
			}
		})
	}
}

func TestNewKubectlSubprocess_NonExecutableBinary(t *testing.T) {
	// Create a non-executable temp file and verify that NewKubectlSubprocess
	// does not panic or exit — it only logs a warning.
	dir := t.TempDir()
	path := dir + "/kubectl"
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho ok\n"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	// Should not panic — just logs a warning about non-executable binary.
	runner := NewKubectlSubprocess(path)
	if runner == nil {
		t.Fatal("expected non-nil runner")
	}
	if runner.Path != path {
		t.Errorf("runner.Path = %q, want %q", runner.Path, path)
	}
}

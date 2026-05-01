package k8s

import (
	"encoding/json"
	"strings"
	"testing"
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
}

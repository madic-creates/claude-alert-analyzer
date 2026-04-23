package k8s

import (
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

func TestAlertPayloadToAlert(t *testing.T) {
	tests := []struct {
		name        string
		payload     shared.AlertPayload
		wantStatus  string
		wantFP      string
		wantLabels  map[string]string
		wantAnnots  map[string]string
	}{
		{
			name: "typical firing alert",
			payload: shared.AlertPayload{
				Fingerprint: "abc123",
				Fields: map[string]string{
					"status":                         "firing",
					"label:alertname":                "HighCPU",
					"label:namespace":                "monitoring",
					"annotation:summary":             "CPU above 90%",
					"annotation:runbook_url":         "https://runbooks.example.com/high-cpu",
				},
			},
			wantStatus: "firing",
			wantFP:     "abc123",
			wantLabels: map[string]string{
				"alertname": "HighCPU",
				"namespace": "monitoring",
			},
			wantAnnots: map[string]string{
				"summary":     "CPU above 90%",
				"runbook_url": "https://runbooks.example.com/high-cpu",
			},
		},
		{
			name: "resolved alert with no annotations",
			payload: shared.AlertPayload{
				Fingerprint: "def456",
				Fields: map[string]string{
					"status":          "resolved",
					"label:alertname": "PodCrashLooping",
					"label:pod":       "my-pod-xyz",
				},
			},
			wantStatus: "resolved",
			wantFP:     "def456",
			wantLabels: map[string]string{
				"alertname": "PodCrashLooping",
				"pod":       "my-pod-xyz",
			},
			wantAnnots: map[string]string{},
		},
		{
			name: "payload with no labels or annotations",
			payload: shared.AlertPayload{
				Fingerprint: "ghi789",
				Fields: map[string]string{
					"status": "firing",
				},
			},
			wantStatus: "firing",
			wantFP:     "ghi789",
			wantLabels: map[string]string{},
			wantAnnots: map[string]string{},
		},
		{
			name: "empty payload",
			payload: shared.AlertPayload{
				Fields: map[string]string{},
			},
			wantStatus: "",
			wantFP:     "",
			wantLabels: map[string]string{},
			wantAnnots: map[string]string{},
		},
		{
			name: "unknown field keys are ignored",
			payload: shared.AlertPayload{
				Fingerprint: "jkl",
				Fields: map[string]string{
					"status":          "firing",
					"label:name":      "TestAlert",
					"unrelated_field": "should be ignored",
					"labelwithout_colon": "also ignored",
				},
			},
			wantStatus: "firing",
			wantFP:     "jkl",
			wantLabels: map[string]string{"name": "TestAlert"},
			wantAnnots: map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AlertPayloadToAlert(tc.payload)

			if got.Status != tc.wantStatus {
				t.Errorf("Status: got %q, want %q", got.Status, tc.wantStatus)
			}
			if got.Fingerprint != tc.wantFP {
				t.Errorf("Fingerprint: got %q, want %q", got.Fingerprint, tc.wantFP)
			}

			if len(got.Labels) != len(tc.wantLabels) {
				t.Errorf("Labels count: got %d, want %d (%v)", len(got.Labels), len(tc.wantLabels), got.Labels)
			}
			for k, want := range tc.wantLabels {
				if got.Labels[k] != want {
					t.Errorf("Labels[%q]: got %q, want %q", k, got.Labels[k], want)
				}
			}

			if len(got.Annotations) != len(tc.wantAnnots) {
				t.Errorf("Annotations count: got %d, want %d (%v)", len(got.Annotations), len(tc.wantAnnots), got.Annotations)
			}
			for k, want := range tc.wantAnnots {
				if got.Annotations[k] != want {
					t.Errorf("Annotations[%q]: got %q, want %q", k, got.Annotations[k], want)
				}
			}
		})
	}
}

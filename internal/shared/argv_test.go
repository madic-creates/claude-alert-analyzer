package shared

import (
	"strings"
	"testing"
)

func TestValidateArgv_Empty(t *testing.T) {
	if err := ValidateArgv(nil); err == nil {
		t.Fatalf("nil argv should be rejected")
	}
	if err := ValidateArgv([]string{}); err == nil {
		t.Fatalf("empty argv should be rejected")
	}
}

func TestValidateArgv_AcceptsTypicalCommand(t *testing.T) {
	if err := ValidateArgv([]string{"df", "-h"}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateArgv_TooManyElements(t *testing.T) {
	args := make([]string, MaxArgvElements+1)
	for i := range args {
		args[i] = "x"
	}
	err := ValidateArgv(args)
	if err == nil {
		t.Fatalf("expected error for %d elements", len(args))
	}
	if !strings.Contains(err.Error(), "maximum") {
		t.Errorf("error should mention maximum, got: %v", err)
	}
}

func TestValidateArgv_RejectionClasses(t *testing.T) {
	cases := []struct {
		name      string
		argv      []string
		wantInErr string
	}{
		{"empty element", []string{"ls", ""}, "empty"},
		{"whitespace-only element", []string{"ls", " "}, "whitespace-only"},
		{"oversized element", []string{"cat", strings.Repeat("A", MaxArgLen+1)}, "maximum length"},
		{"null byte", []string{"cat", "/etc/\x00passwd"}, "null byte"},
		{"newline", []string{"cat", "foo\nbar"}, "newline"},
		{"carriage return", []string{"cat", "foo\rbar"}, "newline"},
		{"leading space", []string{"sed", " -i"}, "leading or trailing whitespace"},
		{"trailing tab", []string{"cat", "foo\t"}, "leading or trailing whitespace"},
		{"embedded tab (C0)", []string{"cat", "fo\to"}, "control character"},
		{"DEL", []string{"cat", "foo\x7fbar"}, "control character"},
		{"C1 control U+0080", []string{"cat", "foo\u0080bar"}, "control character"},
		{"C1 control U+009F", []string{"cat", "foo\u009fbar"}, "control character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArgv(tc.argv)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q should contain %q", err, tc.wantInErr)
			}
		})
	}
}

func TestValidateArgv_TotalByteCap(t *testing.T) {
	argSize := 1024
	numArgs := (MaxTotalArgBytes / argSize) + 1
	args := make([]string, numArgs+1)
	args[0] = "cat"
	for i := 1; i <= numArgs; i++ {
		args[i] = strings.Repeat("A", argSize)
	}
	err := ValidateArgv(args)
	if err == nil {
		t.Fatalf("expected error for total size > %d bytes", MaxTotalArgBytes)
	}
	if !strings.Contains(err.Error(), "total size") {
		t.Errorf("error should mention total size, got: %v", err)
	}
}

func TestValidateArgv_ExactLimits(t *testing.T) {
	args := []string{"cat", strings.Repeat("A", MaxArgLen)}
	if err := ValidateArgv(args); err != nil {
		t.Fatalf("unexpected error at exact per-element limit: %v", err)
	}
}

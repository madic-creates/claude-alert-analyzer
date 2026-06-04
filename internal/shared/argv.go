package shared

import (
	"fmt"
	"strings"
)

// Argv-shape limits applied to command arrays emitted by Claude tool calls.
// A hallucinatory or adversarial model could otherwise emit oversized argv to
// OOM shellQuote, fill structured logs with multi-megabyte "command" fields,
// or smuggle control characters that defeat exact-match denylist lookups
// downstream. Used by checkmk's parseCommandInput and k8s's parseKubectlInput.
const (
	// MaxArgvElements caps the number of elements in a single command array.
	// Real diagnostic commands rarely need more than a handful of arguments.
	MaxArgvElements = 64
	// MaxArgLen caps the byte length of a single argument. Arguments longer
	// than this are almost certainly not a real command option; the cap
	// prevents shellQuote from allocating huge strings.
	MaxArgLen = 4096
	// MaxTotalArgBytes caps the combined byte length of all arguments. The
	// per-element limits alone allow up to MaxArgvElements * MaxArgLen
	// (256 KB); the total cap closes that gap so that shellQuote output and
	// log fields stay bounded even when many arguments are near their
	// individual limit. Real diagnostic commands (df -h, ps aux,
	// cat /path/to/file) never approach this ceiling.
	MaxTotalArgBytes = 16384
)

// ValidateArgv applies byte-level structural checks to an argv produced from a
// Claude tool call. It rejects empty/oversized arrays, empty or
// whitespace-only elements, oversized elements, null bytes, newlines,
// surrounding whitespace, C0/DEL/C1 control characters, Unicode line
// terminators U+2028/U+2029, and total byte overflow. Callers layer their
// own verb/flag policy on top of the validated argv. The C0/DEL/C1 sweep is
// the authoritative backstop; the explicit null and newline checks fire first
// only so callers see a targeted error message instead of the generic
// "control character 0x000a".
//
// The leading/trailing-whitespace check closes a specific denylist-bypass:
// an argument like " -i" would shift byte positions and bypass a sed -i
// denylist check that inspects arg[:2] for "-i"/"-I" (" -i"[:2] is " -",
// not "-i"). Embedded tabs and C1 characters (U+0080..U+009F) likewise
// defeat exact-match denylist lookups: "-exec\t" and "-exec" both
// pass TrimSpace unchanged but never equal the "-exec" key in a denylist
// map. U+2028/U+2029 are rejected for the same reason: they are not in the
// C0/DEL/C1 range so unicode.IsControl misses them, yet "-exec\u2028" would
// bypass the findExecFlags map lookup that blocks "-exec".
func ValidateArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}
	if len(argv) > MaxArgvElements {
		return fmt.Errorf("command has %d elements, maximum is %d", len(argv), MaxArgvElements)
	}
	totalBytes := 0
	for i, arg := range argv {
		if arg == "" {
			return fmt.Errorf("argument %d is empty", i)
		}
		if strings.TrimSpace(arg) == "" {
			return fmt.Errorf("argument %d is whitespace-only", i)
		}
		if len(arg) > MaxArgLen {
			return fmt.Errorf("argument %d exceeds maximum length of %d bytes", i, MaxArgLen)
		}
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("argument %d contains null byte", i)
		}
		if strings.ContainsRune(arg, '\n') || strings.ContainsRune(arg, '\r') {
			return fmt.Errorf("argument %d contains newline", i)
		}
		if strings.TrimSpace(arg) != arg {
			return fmt.Errorf("argument %d has leading or trailing whitespace", i)
		}
		for _, r := range arg {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u2028' || r == '\u2029' {
				return fmt.Errorf("argument %d contains control character 0x%04x", i, r)
			}
		}
		totalBytes += len(arg)
	}
	if totalBytes > MaxTotalArgBytes {
		return fmt.Errorf("command total size %d bytes exceeds maximum of %d bytes", totalBytes, MaxTotalArgBytes)
	}
	return nil
}

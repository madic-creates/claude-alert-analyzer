package checkmk

import (
	"testing"
)

func TestValidateServiceName_Valid(t *testing.T) {
	valid := []string{"sshd", "nginx", "k3s-agent", "postfix@-", "docker.service"}
	for _, name := range valid {
		if !validServiceName(name) {
			t.Errorf("expected valid: %s", name)
		}
	}
}

func TestValidateServiceName_Invalid(t *testing.T) {
	invalid := []string{"$(whoami)", "; rm -rf /", "foo bar", "a&b", "x|y", "test`cmd`"}
	for _, name := range invalid {
		if validServiceName(name) {
			t.Errorf("expected invalid: %s", name)
		}
	}
}

func TestDetectCategory_CPU(t *testing.T) {
	cat := detectCategory("CPU load", "CRIT - 15min load 12.5")
	if cat != categoryCPU {
		t.Errorf("expected categoryCPU, got %v", cat)
	}
}

func TestDetectCategory_Disk(t *testing.T) {
	cat := detectCategory("Filesystem /", "CRIT - 95% used")
	if cat != categoryDisk {
		t.Errorf("expected categoryDisk, got %v", cat)
	}
}

func TestDetectCategory_Memory(t *testing.T) {
	cat := detectCategory("Memory", "WARN - 85% used")
	if cat != categoryMemory {
		t.Errorf("expected categoryMemory, got %v", cat)
	}
}

func TestDetectCategory_Service(t *testing.T) {
	cat := detectCategory("systemd sshd", "running")
	if cat != categoryService {
		t.Errorf("expected categoryService, got %v", cat)
	}
}

func TestDetectCategory_Generic(t *testing.T) {
	cat := detectCategory("PING", "OK - rta 0.5ms")
	if cat != categoryGeneric {
		t.Errorf("expected categoryGeneric, got %v", cat)
	}
}

func TestBuildCommands_AlwaysIncludesJournalctl(t *testing.T) {
	cmds := buildCommands(categoryGeneric, "")
	found := false
	for _, cmd := range cmds {
		if cmd.argv[0] == "journalctl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected journalctl in generic commands")
	}
}

func TestBuildCommands_ServiceCategory(t *testing.T) {
	cmds := buildCommands(categoryService, "sshd")
	found := false
	for _, cmd := range cmds {
		if cmd.argv[0] == "systemctl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected systemctl in service commands")
	}
}

func TestBuildCommands_InvalidServiceName_NoServiceCommands(t *testing.T) {
	cmds := buildCommands(categoryService, "$(evil)")
	for _, cmd := range cmds {
		if cmd.argv[0] == "systemctl" {
			t.Errorf("should not have systemctl with invalid name: %v", cmd.argv)
		}
		if cmd.argv[0] == "journalctl" {
			for _, a := range cmd.argv {
				if a == "-u" {
					t.Errorf("should not have journalctl -u with invalid name: %v", cmd.argv)
				}
			}
		}
	}
}

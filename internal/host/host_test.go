package host

import (
	"testing"
)

func b(v bool) *bool { return &v }

func TestAnalyzeDefaults(t *testing.T) {
	got := Analyze(nil, nil)
	ids := map[string]bool{}
	for _, f := range got {
		ids[f.RuleID] = true
	}
	for _, id := range []string{"HOST001", "HOST002", "HOST003", "HOST004"} {
		if !ids[id] {
			t.Errorf("expected %s with no daemon config", id)
		}
	}
	if ids["HOST005"] {
		t.Error("HOST005 should not fire without docker info")
	}
}

func TestAnalyzeHardened(t *testing.T) {
	daemon := &DaemonConfig{ICC: b(false), UsernsRemap: "default", LiveRestore: b(true), NoNewPrivileges: b(true)}
	info := &Info{SecurityOptions: []string{"name=seccomp,profile=builtin", "name=rootless"}}
	if got := Analyze(daemon, info); len(got) != 0 {
		t.Errorf("expected no findings for a hardened daemon, got %+v", got)
	}
}

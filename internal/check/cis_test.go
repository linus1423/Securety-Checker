package check

import "testing"

func TestCISControls(t *testing.T) {
	controls := CISControls()
	if len(controls) == 0 {
		t.Fatal("expected some CIS controls from rule refs")
	}

	// Sections must be sorted numerically: "4.2" before "4.10".
	idx := map[string]int{}
	for i, c := range controls {
		idx[c.Section] = i
	}
	if i42, ok1 := idx["4.2"]; ok1 {
		if i410, ok2 := idx["4.10"]; ok2 && !(i42 < i410) {
			t.Errorf("expected 4.2 before 4.10, got %d vs %d", i42, i410)
		}
	}

	// 4.1 (root user) must include DF001 and CMP006.
	for _, c := range controls {
		if c.Section == "4.1" {
			has := map[string]bool{}
			for _, r := range c.Rules {
				has[r] = true
			}
			if !has["DF001"] || !has["CMP006"] {
				t.Errorf("CIS 4.1 should include DF001 and CMP006, got %v", c.Rules)
			}
		}
	}
}

func TestLessSection(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"4.2", "4.10", true},
		{"4.10", "4.2", false},
		{"4.1", "5.1", true},
		{"5.3", "5.3", false},
	}
	for _, c := range cases {
		if got := lessSection(c.a, c.b); got != c.want {
			t.Errorf("lessSection(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

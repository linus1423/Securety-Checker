package check

import (
	"sort"
	"strings"
)

// cisPrefix is how a CIS reference is stored in a rule's Refs (see cis()).
const cisPrefix = "CIS Docker Benchmark "

// CISControl is one CIS Docker Benchmark recommendation that secchk maps rules
// to, with the rules that check it.
type CISControl struct {
	Section string   // e.g. "4.1"
	Rules   []string // rule IDs that enforce this control, sorted
}

// CISControls returns the CIS Docker Benchmark sections secchk's static rules
// map to, each with its rules, sorted by section. This is the universe of
// controls secchk can report on, so a compliance report can mark a control
// passed when no rule fired and failed when one did.
func CISControls() []CISControl {
	bySection := map[string]map[string]bool{}
	add := func(ruleID string, refs []string) {
		for _, r := range refs {
			if !strings.HasPrefix(r, cisPrefix) {
				continue
			}
			section := strings.TrimSpace(strings.TrimPrefix(r, cisPrefix))
			if section == "" {
				continue
			}
			if bySection[section] == nil {
				bySection[section] = map[string]bool{}
			}
			bySection[section][ruleID] = true
		}
	}
	for _, r := range DockerfileRules {
		add(r.ID, r.Refs)
	}
	for _, r := range ComposeRules {
		add(r.ID, r.Refs)
	}

	out := make([]CISControl, 0, len(bySection))
	for section, ruleSet := range bySection {
		rules := make([]string, 0, len(ruleSet))
		for id := range ruleSet {
			rules = append(rules, id)
		}
		sort.Strings(rules)
		out = append(out, CISControl{Section: section, Rules: rules})
	}
	sort.Slice(out, func(i, j int) bool { return lessSection(out[i].Section, out[j].Section) })
	return out
}

// lessSection orders dotted section numbers numerically ("4.2" before "4.10").
func lessSection(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, bi := atoiSafe(as[i]), atoiSafe(bs[i])
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

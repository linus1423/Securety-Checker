package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/linus1423/Securety-Checker/internal/check"
)

// writeCIS renders a CIS Docker Benchmark compliance view: for every control
// secchk maps rules to, it reports PASS (no rule fired) or FAIL (at least one
// finding), with the failing rules named. Controls secchk does not cover are
// not listed, so the report never claims compliance it did not check.
func writeCIS(w io.Writer, r Result) error {
	controls := check.CISControls()

	// rule IDs that produced at least one finding
	fired := map[string]int{}
	for _, f := range r.Findings {
		fired[f.RuleID]++
	}

	passed := 0
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "CIS\tSTATUS\tREGELN\tBEFUNDE\n")
	for _, ctrl := range controls {
		var failing []string
		total := 0
		for _, id := range ctrl.Rules {
			if n := fired[id]; n > 0 {
				failing = append(failing, id)
				total += n
			}
		}
		status := "PASS"
		detail := joinRules(ctrl.Rules)
		if len(failing) > 0 {
			status = "FAIL"
			detail = joinRules(failing)
		} else {
			passed++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", ctrl.Section, status, detail, total)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d/%d geprüfte CIS-Kontrollen erfüllt.\n", passed, len(controls))
	return err
}

func joinRules(rules []string) string {
	out := ""
	for i, r := range rules {
		if i > 0 {
			out += ", "
		}
		out += r
	}
	if out == "" {
		return "-"
	}
	return out
}

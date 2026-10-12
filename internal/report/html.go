package report

import (
	"html/template"
	"io"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// htmlView is the data passed to the HTML template.
type htmlView struct {
	Root      string
	FileCount int
	Summary   string
	Counts    []countRow
	Findings  []htmlFinding
}

type countRow struct {
	Severity string
	Count    int
}

type htmlFinding struct {
	Severity    string
	RuleID      string
	Location    string
	Title       string
	Confidence  string
	Message     string
	Remediation string
	Reference   string
}

// writeHTML renders a self-contained, dependency-free HTML report. It works in
// both light and dark color schemes and needs no external assets.
func writeHTML(w io.Writer, r Result) error {
	view := htmlView{
		Root:      r.Root,
		FileCount: len(r.Files),
		Summary:   finding.Summary(r.Findings),
	}
	counts := finding.Counts(r.Findings)
	for s := finding.SeverityCritical; s >= finding.SeverityInfo; s-- {
		if n := counts[s]; n > 0 {
			view.Counts = append(view.Counts, countRow{Severity: s.String(), Count: n})
		}
	}
	for _, f := range r.Findings {
		loc := f.Location.File
		if f.Location.Line > 0 {
			loc = locWithLine(f.Location.File, f.Location.Line)
		}
		hf := htmlFinding{
			Severity:    f.Severity.String(),
			RuleID:      f.RuleID,
			Location:    loc,
			Title:       f.Title,
			Message:     f.Message,
			Remediation: f.Remediation,
		}
		if f.Confidence != finding.ConfidenceHigh {
			hf.Confidence = f.Confidence.String()
		}
		if len(f.References) > 0 {
			hf.Reference = f.References[0]
		}
		view.Findings = append(view.Findings, hf)
	}
	return htmlTemplate.Execute(w, view)
}

func locWithLine(file string, line int) string {
	return file + ":" + itoa(line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secchk Report</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --border: #e0e0e0; --card: #f7f7f7;
  --crit: #b00020; --high: #d84315; --med: #e8a200; --low: #2e7d32; --info: #546e7a;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #16181c; --fg: #e8e8e8; --muted: #9aa0a6; --border: #30343b; --card: #1f2329;
    --crit: #ff5370; --high: #ff8a65; --med: #ffca28; --low: #81c784; --info: #90a4ae; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color: var(--muted); margin-bottom: 20px; }
.counts { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }
.pill { padding: 4px 10px; border-radius: 999px; font-size: 13px; font-weight: 600;
  border: 1px solid var(--border); background: var(--card); }
.badge { display: inline-block; min-width: 68px; text-align: center; padding: 2px 8px;
  border-radius: 6px; font-size: 12px; font-weight: 700; color: #fff; text-transform: uppercase; }
.b-critical { background: var(--crit); } .b-high { background: var(--high); }
.b-medium { background: var(--med); color: #1a1a1a; } .b-low { background: var(--low); }
.b-info { background: var(--info); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
.fix { color: var(--muted); font-size: 13px; margin-top: 4px; }
.empty { padding: 32px; text-align: center; color: var(--muted); border: 1px dashed var(--border); border-radius: 8px; }
a { color: inherit; }
</style>
</head>
<body>
<h1>secchk Security Report</h1>
<div class="sub">{{.Root}} · {{.FileCount}} geprüfte Datei(en){{if .Summary}} · {{.Summary}}{{end}}</div>
{{if .Findings}}
<div class="counts">
{{range .Counts}}<span class="pill">{{.Count}} {{.Severity}}</span>{{end}}
</div>
<table>
<thead><tr><th>Schwere</th><th>Regel</th><th>Ort</th><th>Befund</th></tr></thead>
<tbody>
{{range .Findings}}
<tr>
<td><span class="badge b-{{.Severity}}">{{.Severity}}</span></td>
<td><code>{{.RuleID}}</code></td>
<td><code>{{.Location}}</code></td>
<td>
  {{.Title}}{{if .Confidence}} <span class="pill">confidence: {{.Confidence}}</span>{{end}}
  {{if .Message}}<div class="fix">{{.Message}}</div>{{end}}
  {{if .Remediation}}<div class="fix">Fix: {{.Remediation}}</div>{{end}}
  {{if .Reference}}<div class="fix">Siehe: <a href="{{.Reference}}">{{.Reference}}</a></div>{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<div class="empty">Keine Befunde.</div>
{{end}}
</body>
</html>
`))

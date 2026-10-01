package report

import (
	"html/template"
	"io"
	"sort"

	"github.com/Warzuponus/achilles/internal/advisor"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/review"
	"github.com/Warzuponus/achilles/internal/threatmodel"
)

// HTMLReport is everything the HTML report can render. The findings come from the
// scan; Review/Advice/ThreatModel are the LLM agents' outputs (nil when the agent
// didn't run) — folding them in is what turns a findings list into fix advice.
type HTMLReport struct {
	Target      string
	GeneratedAt string
	Tools       []string
	Scan        model.Scan
	Review      *review.Review
	Advice      *advisor.Advice
	ThreatModel *threatmodel.ThreatModel
}

// severityOrder ranks severities for display (most severe first).
var severityRank = map[model.Severity]int{
	model.SeverityCritical: 0, model.SeverityHigh: 1, model.SeverityMedium: 2,
	model.SeverityLow: 3, model.SeverityInfo: 4, model.SeverityUnknown: 5,
}

type htmlView struct {
	HTMLReport
	Total      int
	Counts     []severityCount // ordered, only non-zero
	Findings   []model.Finding // in-scope, sorted by severity
	HasReview  bool
	HasAdvice  bool
	HasThreats bool
}

type severityCount struct {
	Severity model.Severity
	Count    int
}

// WriteHTML renders a self-contained (inline CSS, no external assets) HTML report.
func WriteHTML(w io.Writer, r HTMLReport) error {
	counts := map[model.Severity]int{}
	var findings []model.Finding
	for _, f := range r.Scan.Findings {
		if f.Shadow {
			continue
		}
		findings = append(findings, f)
		counts[f.Severity]++
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank[findings[i].Severity] < severityRank[findings[j].Severity]
	})
	var ordered []severityCount
	for sev, rank := range severityRank {
		_ = rank
		if counts[sev] > 0 {
			ordered = append(ordered, severityCount{sev, counts[sev]})
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		return severityRank[ordered[i].Severity] < severityRank[ordered[j].Severity]
	})

	v := htmlView{
		HTMLReport: r,
		Total:      len(findings),
		Counts:     ordered,
		Findings:   findings,
		HasReview:  r.Review != nil && (r.Review.Summary != "" || len(r.Review.Risks) > 0),
		HasAdvice:  r.Advice != nil && len(r.Advice.Upgrades) > 0,
		HasThreats: r.ThreatModel != nil && (len(r.ThreatModel.Threats) > 0 || len(r.ThreatModel.Components) > 0),
	}
	return htmlTmpl.Execute(w, v)
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sev": func(s model.Severity) string { return string(s) },
	"pct": func(f float64) float64 { return f * 100 },
}).Parse(htmlDoc))

const htmlDoc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Achilles Security Report — {{.Target}}</title>
<style>
  :root{
    --bg:#0f1420; --panel:#171e2e; --panel2:#1e2740; --text:#e7ecf5; --muted:#93a0b8;
    --border:#2a3550; --accent:#7c9cff; --code:#0b0f1a;
    --critical:#ff5c7a; --high:#ff8a4c; --medium:#ffcc4d; --low:#5cc8ff; --info:#93a0b8; --unknown:#93a0b8;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#f5f7fb; --panel:#fff; --panel2:#f0f3f9; --text:#111726; --muted:#5a6784;
      --border:#dde3ef; --accent:#3b5bdb; --code:#f3f5fa;
      --critical:#e5384f; --high:#d9631a; --medium:#b8860b; --low:#1f7aa8; --info:#5a6784; --unknown:#5a6784; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
  .wrap{max-width:960px;margin:0 auto;padding:32px 20px 80px}
  header h1{margin:0 0 4px;font-size:26px;letter-spacing:-.02em}
  header .meta{color:var(--muted);font-size:13px}
  header .meta code{color:var(--text)}
  .cards{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;
    padding:14px 18px;min-width:104px;flex:1}
  .card .n{font-size:28px;font-weight:700;line-height:1}
  .card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin-top:6px}
  section{background:var(--panel);border:1px solid var(--border);border-radius:14px;
    padding:22px 24px;margin:20px 0}
  section h2{margin:0 0 14px;font-size:18px;display:flex;align-items:center;gap:10px}
  section h2 .tag{font-size:11px;font-weight:600;color:var(--muted);border:1px solid var(--border);
    border-radius:999px;padding:2px 9px;text-transform:uppercase;letter-spacing:.05em}
  .lead{color:var(--muted);margin:-4px 0 16px}
  .badge{display:inline-block;font-size:11px;font-weight:700;border-radius:6px;padding:2px 8px;
    text-transform:uppercase;letter-spacing:.04em;color:#0b0f1a}
  .b-critical{background:var(--critical)} .b-high{background:var(--high)}
  .b-medium{background:var(--medium)} .b-low{background:var(--low)}
  .b-info,.b-unknown{background:var(--info)}
  .risk{border-left:3px solid var(--border);padding:2px 0 2px 14px;margin:14px 0}
  .risk h3{margin:0 0 4px;font-size:15px}
  .risk .rec{color:var(--accent);margin-top:6px}
  table{width:100%;border-collapse:collapse;font-size:14px}
  th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top}
  th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
  .tbl-scroll{overflow-x:auto}
  details{border:1px solid var(--border);border-radius:10px;margin:8px 0;background:var(--panel2)}
  details>summary{cursor:pointer;padding:11px 14px;display:flex;gap:10px;align-items:center;
    list-style:none;font-weight:600}
  details>summary::-webkit-details-marker{display:none}
  details>summary .rule{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  details>summary .loc{color:var(--muted);font-size:12px;margin-left:auto;
    font-family:ui-monospace,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:45%}
  .body{padding:0 14px 14px}
  .msg{margin:6px 0 12px}
  .kv{color:var(--muted);font-size:13px;margin:2px 0}
  .fix{background:var(--code);border:1px solid var(--border);border-radius:8px;padding:12px;margin-top:10px}
  .fix h4{margin:0 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--accent)}
  pre{margin:8px 0 0;overflow-x:auto;background:var(--code);border-radius:8px;padding:12px;
    font:12px/1.5 ui-monospace,Menlo,monospace}
  .empty{color:var(--muted);text-align:center;padding:20px}
  footer{color:var(--muted);font-size:12px;text-align:center;margin-top:32px}
  .verdict{font-size:12px;font-weight:700;border-radius:6px;padding:1px 7px;border:1px solid var(--border)}
  .sec{color:var(--critical);font-weight:700;font-size:12px}
</style>
</head>
<body><div class="wrap">
<header>
  <h1>Achilles Security Report</h1>
  <div class="meta">Target <code>{{.Target}}</code> · {{.GeneratedAt}} · {{len .Tools}} scanner(s): {{range $i,$t := .Tools}}{{if $i}}, {{end}}{{$t}}{{end}}</div>
</header>

<div class="cards">
  <div class="card"><div class="n">{{.Total}}</div><div class="l">Findings</div></div>
  {{range .Counts}}<div class="card"><div class="n">{{.Count}}</div><div class="l"><span class="badge b-{{sev .Severity}}">{{sev .Severity}}</span></div></div>{{end}}
</div>

{{if .HasReview}}
<section>
  <h2>Systemic Risks <span class="tag">AI review</span></h2>
  <p class="lead">{{.Review.Summary}}</p>
  {{range .Review.Risks}}
  <div class="risk">
    <h3><span class="badge b-{{.Severity}}">{{.Severity}}</span> {{.Title}}{{if .Area}} <span class="kv">· {{.Area}}</span>{{end}}</h3>
    <div>{{.Rationale}}</div>
    <div class="rec">→ {{.Recommendation}}</div>
  </div>
  {{end}}
</section>
{{end}}

{{if .HasAdvice}}
<section>
  <h2>Dependency Upgrade Plan <span class="tag">AI advisor</span></h2>
  {{if .Advice.Summary}}<p class="lead">{{.Advice.Summary}}</p>{{end}}
  <div class="tbl-scroll"><table>
    <tr><th>Package</th><th>Upgrade</th><th>Type</th><th>Merge risk</th><th>Why</th></tr>
    {{range .Advice.Upgrades}}
    <tr>
      <td><strong>{{.Package}}</strong>{{if .SecurityDriven}} <span class="sec">● security</span>{{end}}</td>
      <td>{{.CurrentVersion}}{{if .RecommendedVersion}} → {{.RecommendedVersion}}{{end}}</td>
      <td>{{.UpgradeType}}</td>
      <td>{{.MergeRisk}}</td>
      <td>{{.Rationale}}</td>
    </tr>
    {{end}}
  </table></div>
</section>
{{end}}

{{if .HasThreats}}
<section>
  <h2>Threat Model <span class="tag">STRIDE</span></h2>
  <p class="lead">Trust zones: {{range $i,$z := .ThreatModel.TrustZones}}{{if $i}}, {{end}}{{$z.Name}}{{end}}</p>
  <div class="tbl-scroll"><table>
    <tr><th>Risk</th><th>Category</th><th>Threat</th><th>Mitigation</th></tr>
    {{range .ThreatModel.Threats}}
    <tr><td><span class="badge b-{{.Risk}}">{{.Risk}}</span></td><td>{{.Category}}</td>
      <td><strong>{{.Name}}</strong>{{if .Description}}<div class="kv">{{.Description}}</div>{{end}}</td>
      <td>{{.Mitigation}}</td></tr>
    {{end}}
  </table></div>
</section>
{{end}}

<section>
  <h2>Findings</h2>
  {{if .Findings}}
  {{range .Findings}}
  <details>
    <summary><span class="badge b-{{sev .Severity}}">{{sev .Severity}}</span>
      <span class="rule">{{.RuleID}}</span>
      <span class="loc">{{.Location.File}}{{if .Location.Region.StartLine}}:{{.Location.Region.StartLine}}{{end}}</span></summary>
    <div class="body">
      <div class="msg">{{.Message}}</div>
      <div class="kv">Tool: {{.Tool}}</div>
      {{with .Verdict}}
      <div class="kv" style="margin-top:8px"><span class="verdict">{{.Classification}} · {{printf "%.0f%%" (pct .Confidence)}}{{if .Refuted}} · refuted{{else if .Overturned}} · overturned by judge{{end}}</span></div>
      {{if .Reasoning}}<div class="kv">{{.Reasoning}}</div>{{end}}
      {{end}}
      {{with .Remediation}}
      <div class="fix">
        <h4>Suggested fix</h4>
        <div>{{.Summary}}</div>
        {{if .Guidance}}<div class="kv" style="margin-top:6px">{{.Guidance}}</div>{{end}}
        {{if .Diff}}<pre>{{.Diff}}</pre>{{end}}
      </div>
      {{end}}
    </div>
  </details>
  {{end}}
  {{else}}<div class="empty">No findings. ✅</div>{{end}}
</section>

<footer>Generated by Achilles · LLM-assisted SAST</footer>
</div></body></html>`

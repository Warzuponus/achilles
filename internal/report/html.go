package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/advisor"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
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
	Findings   []findingView   // actionable findings: severity, then AI-confirmed first
	Dismissed  []findingView   // ruled out by the AI review; listed so the call is auditable
	Hardening  []findingView   // dismissed as hardening notes: real weaknesses another control already stops
	Suppressed []findingView   // suppressed by a comment in the scanned code; listed with the reason
	Hunted     []findingView   // hunt-mode candidates the AI review did not confirm
	Confirmed  int             // actionable findings the AI review confirmed
	HasReview  bool
	HasAdvice  bool
	HasThreats bool
	Incomplete string // non-empty: the scan is partial; names the tools that failed
	// Scanner configuration found in the scanned repository: in effect, and the
	// part of it that the change under review modifies.
	RepoConfig        string
	RepoConfigChanged string
	ToolPlanHeader    string
	ToolPlan          []string
	Coverage          string // one line on how much of the scan the AI review covered
	Uncovered         string // detected languages no scanner that ran covers; empty when none
	CoverageOK        bool   // false when the AI review was absent or partial
	Summary           string // plain-language headline
}

// findingView is a finding prepared for display: secrets masked, code bounded.
type findingView struct {
	model.Finding
	Status  string // AI review status: confirmed | needs validation | needs review | not reviewed | overturned | dismissed | hardening
	Snippet string // redacted, bounded code; empty for secret findings
	Message string // redacted
	Secret  bool
	// VerdictFix is the triage pass's fix idea, shown only when no fuller
	// remediation exists for the finding.
	VerdictFix string
}

// DetailRows are the verdict's actionable detail (attacker, impact, assessed
// severity, open questions, unchecked references), credentials masked.
func (v findingView) DetailRows() []model.DetailLine {
	if v.Verdict == nil || v.Secret {
		return nil
	}
	rows := v.Verdict.Details()
	for i := range rows {
		rows[i].Text = redact.Secrets(rows[i].Text)
	}
	return rows
}

// PathRows is the source-to-sink path for the finding, one step per row,
// credentials masked; PathSource says who traced it.
func (v findingView) PathRows() []string {
	steps, _ := v.SourcePath()
	rows := make([]string, 0, len(steps))
	for _, s := range steps {
		rows = append(rows, redact.Secrets(s.String()))
	}
	return rows
}

// PathSource names who traced the path PathRows shows.
func (v findingView) PathSource() string {
	_, from := v.SourcePath()
	return from
}

// gateRow is one answered question of the AI review, for display.
type gateRow struct{ Question, Answer, Evidence string }

// GateRows lists the gate answers of the verdict that carry information; empty
// when the review gave none (older runs, or a model that omitted them).
func (v findingView) GateRows() []gateRow {
	if v.Verdict == nil || v.Verdict.Gates == nil {
		return nil
	}
	g := v.Verdict.Gates
	var rows []gateRow
	for _, r := range []struct {
		q string
		g model.Gate
	}{
		{"Designed behavior?", g.DesignedBehavior}, {"Reachable?", g.Reachable},
		{"Attacker-controlled?", g.AttackerControlled}, {"Sanitized?", g.Sanitized},
		{"New capability?", g.NewCapability},
	} {
		if r.g.Answer == "" {
			continue
		}
		rows = append(rows, gateRow{r.q, string(r.g.Answer), redact.Secrets(r.g.Evidence)})
	}
	return rows
}

// StabilityLine says how consistent the model was when asked more than once.
func (v findingView) StabilityLine() string {
	if v.Verdict == nil || v.Verdict.Stability == nil || v.Verdict.Stability.Samples < 2 {
		return ""
	}
	st := v.Verdict.Stability
	var parts []string
	for _, c := range []model.Classification{model.ClassTruePositive, model.ClassFalsePositive, model.ClassUncertain} {
		if n := st.Classifications[c]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, c))
		}
	}
	line := fmt.Sprintf("Asked %d times: %s", st.Samples, strings.Join(parts, ", "))
	if !st.Unanimous() {
		line += ". The answers disagreed, so this is never dismissed automatically."
	}
	return line
}

// RegressionTestView is the proposed test with credentials masked; nil when there
// is none or the finding is a credential.
func (v findingView) RegressionTestView() *model.RegressionTest {
	if v.Secret || v.Remediation == nil || v.Remediation.RegressionTest == nil {
		return nil
	}
	t := *v.Remediation.RegressionTest
	t.Code = redact.Secrets(t.Code)
	t.Description = redact.Secrets(t.Description)
	return &t
}

// FixLine describes the re-scan result of the suggested patch; empty when the
// patch was not re-scanned.
func (v findingView) FixLine() string {
	r := v.Remediation
	if r == nil || r.Verification == nil {
		return ""
	}
	fv := r.Verification
	switch fv.Status {
	case model.FixVerified:
		return "Verified by re-scan: the scanner that reported this no longer does after the patch, and reported nothing new. That does not prove the change is correct; review and test it."
	default:
		line := "Not verified (" + strings.ReplaceAll(string(fv.Status), "_", " ") + ")"
		if fv.Detail != "" {
			line += ": " + redact.Secrets(fv.Detail)
		}
		return line
	}
}

// DeepLine summarizes a --deep-verify pass over this finding.
func (v findingView) DeepLine() string {
	d := v.Deep
	if d == nil {
		return ""
	}
	if d.Aborted != "" {
		return fmt.Sprintf("Deep check stopped after %d step(s): %s", d.Steps, redact.Secrets(d.Aborted))
	}
	line := fmt.Sprintf("Deep check (%d step(s)): %s, %.0f%% confident", d.Steps, d.Conclusion, d.Confidence*100)
	if d.Reasoning != "" {
		line += ". " + redact.Secrets(d.Reasoning)
	}
	return line
}

// statusClass is the CSS-safe form of Status.
func (v findingView) StatusClass() string { return strings.ReplaceAll(v.Status, " ", "-") }

type severityCount struct {
	Severity model.Severity
	Count    int
}

// maxSnippetLines bounds the code shown per finding so a report stays readable.
const maxSnippetLines = 30

func toView(f model.Finding) findingView {
	v := findingView{Finding: f, Secret: f.IsSecret(), Message: redact.Secrets(f.Message)}
	switch {
	case f.Verdict == nil:
		v.Status = "not reviewed"
	case f.Verdict.Overturned:
		v.Status = "overturned"
	case f.Verdict.Hardening():
		v.Status = "hardening"
	case f.Verdict.Dismissed():
		v.Status = "dismissed"
	case f.Verdict.HighConfidence():
		v.Status = "confirmed"
	case f.Verdict.Classification == model.ClassUncertain:
		v.Status = "needs validation"
	default:
		v.Status = "needs review"
	}
	if f.Verdict != nil && f.Verdict.SuggestedFix != "" && (f.Remediation == nil || f.Remediation.Summary == "") {
		v.VerdictFix = redact.Secrets(f.Verdict.SuggestedFix)
	}
	if !v.Secret && f.CodeContext != "" {
		lines := strings.Split(strings.TrimRight(redact.Prompt(f.CodeContext), "\n"), "\n")
		if len(lines) > maxSnippetLines {
			lines = append(lines[:maxSnippetLines], "…")
		}
		v.Snippet = strings.Join(lines, "\n")
	}
	return v
}

// statusRank orders findings within a severity: what the AI confirmed first.
func statusRank(s string) int {
	switch s {
	case "confirmed":
		return 0
	case "overturned":
		return 1
	case "needs validation":
		return 2
	case "needs review":
		return 3
	default:
		return 4
	}
}

// WriteHTML renders a self-contained (inline CSS, no external assets) HTML report.
func WriteHTML(w io.Writer, r HTMLReport) error {
	counts := map[model.Severity]int{}
	var findings, dismissed []findingView
	confirmed := 0
	for _, f := range r.Scan.Findings {
		if f.Shadow {
			continue
		}
		fv := toView(f)
		findings = append(findings, fv)
		counts[f.Severity]++
		if fv.Status == "confirmed" {
			confirmed++
		}
	}
	var hardening []findingView
	for _, f := range r.Scan.Dismissed {
		if f.Verdict != nil && f.Verdict.Hardening() {
			hardening = append(hardening, toView(f))
			continue
		}
		dismissed = append(dismissed, toView(f))
	}
	var suppressed []findingView
	for _, f := range r.Scan.Suppressed {
		if f.Suppression != nil {
			suppressed = append(suppressed, toView(f))
		}
	}
	var hunted []findingView
	for _, f := range r.Scan.Hunted {
		hunted = append(hunted, toView(f))
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		return statusRank(a.Status) < statusRank(b.Status)
	})
	var ordered []severityCount
	for sev := range severityRank {
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
		Dismissed:  dismissed,
		Hardening:  hardening,
		Suppressed: suppressed,
		Hunted:     hunted,
		Confirmed:  confirmed,
		HasReview:  r.Review != nil && (r.Review.Summary != "" || len(r.Review.Risks) > 0),
		HasAdvice:  r.Advice != nil && len(r.Advice.Upgrades) > 0,
		HasThreats: r.ThreatModel != nil && (len(r.ThreatModel.Threats) > 0 || len(r.ThreatModel.Components) > 0),
	}
	if len(r.Scan.FailedTools) > 0 {
		v.Incomplete = strings.Join(r.Scan.FailedTools, ", ")
	}
	v.RepoConfig = strings.Join(r.Scan.RepoConfig, "; ")
	v.RepoConfigChanged = strings.Join(r.Scan.RepoConfigChanged, "; ")
	if p := r.Scan.ToolPlan; p != nil {
		v.ToolPlanHeader, v.ToolPlan = toolPlanHeader(p), toolPlanLines(p)
	}
	v.Coverage, v.CoverageOK = coverageLine(r.Scan.Triage)
	v.Uncovered = strings.Join(r.Scan.UncoveredLanguages, ", ")
	v.Summary = summaryLine(v)
	return htmlTmpl.Execute(w, v)
}

// coverageLine says how much of the scan the AI review covered. A report that shows
// verdicts has to show the findings that never got one.
func coverageLine(t *model.TriageStats) (string, bool) {
	if t == nil {
		return "AI verification was not run: findings below are raw scanner output.", false
	}
	if t.Aborted != "" {
		return fmt.Sprintf("The AI review did not complete (%s). It gave a verdict on %d of %d findings; treat everything below as scanner output that was not reviewed.",
			t.Aborted, t.Triaged, t.Total), false
	}
	line := fmt.Sprintf("AI review (%s) gave a verdict on %d of %d findings", t.Model, t.Triaged, t.Total)
	if t.AutoResolved > 0 {
		line += fmt.Sprintf(" (%d of them from analyst feedback on the rule, not from a model review)", t.AutoResolved)
	}
	if t.Reused > 0 {
		line += fmt.Sprintf(" (%d reused from earlier runs: same code, prompt and models)", t.Reused)
	}
	if t.Advisories > 0 {
		line += fmt.Sprintf("; %d dependency advisories are listed as reported (the AI review does not judge known CVEs in dependencies)", t.Advisories)
	}
	if t.Failed > 0 || t.Skipped > 0 {
		line += fmt.Sprintf("; %d failed and %d were not reached (see the run log)", t.Failed, t.Skipped)
		return line + ".", false
	}
	return line + ".", true
}

func summaryLine(v htmlView) string {
	s := fmt.Sprintf("%d actionable finding(s)", v.Total)
	if v.Coverage != "" && v.CoverageOK {
		s += fmt.Sprintf(", %d confirmed by the AI review", v.Confirmed)
	}
	if n := len(v.Dismissed); n > 0 {
		s += fmt.Sprintf("; %d more ruled out as false positives (listed at the end)", n)
	}
	if n := len(v.Hardening); n > 0 {
		s += fmt.Sprintf("; %d hardening note(s), weaknesses another control already stops (listed at the end)", n)
	}
	if n := len(v.Suppressed); n > 0 {
		s += fmt.Sprintf("; %d suppressed by comments in the code (listed at the end)", n)
	}
	if n := len(v.Hunted); n > 0 {
		s += fmt.Sprintf("; %d hunt candidate(s) the AI review did not confirm (listed at the end)", n)
	}
	return s + "."
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
  .alert{border-radius:10px;padding:10px 14px;margin:14px 0;font-size:14px;border:1px solid var(--border)}
  .alert.warn{border-color:var(--high);background:var(--panel2)}
  .alert.ok{border-color:var(--border);color:var(--muted)}
  .status{font-size:11px;font-weight:700;border-radius:6px;padding:1px 7px;border:1px solid var(--border);
    text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  table.gates{margin:8px 0;font-size:13px}
  table.gates td{padding:3px 10px 3px 0;border:0;color:var(--muted)}
  ol.path{margin:4px 0 8px 20px;padding:0;font-size:13px;color:var(--muted)}
  .s-confirmed{color:var(--critical);border-color:var(--critical)}
  .s-overturned,.s-needs-review,.s-needs-validation{color:var(--medium);border-color:var(--medium)}
</style>
</head>
<body><div class="wrap">
<header>
  <h1>Achilles Security Report</h1>
  <div class="meta">Target <code>{{.Target}}</code> · {{.GeneratedAt}} · {{len .Tools}} scanner(s): {{range $i,$t := .Tools}}{{if $i}}, {{end}}{{$t}}{{end}}</div>
</header>

{{if .Incomplete}}<div class="alert warn"><strong>Incomplete scan.</strong> These tools failed to run or could not be read: {{.Incomplete}}. Missing results are not evidence of safety. Run <code>achilles doctor</code> to see what is missing.</div>{{end}}
{{if .RepoConfigChanged}}<div class="alert warn"><strong>This change modifies scanner configuration.</strong> {{.RepoConfigChanged}}. It can hide findings in the same change; review it as part of this scan.</div>{{end}}
{{if .RepoConfig}}<div class="alert">Scanner configuration from the scanned repository was in effect: {{.RepoConfig}}. It can remove findings before Achilles sees them.</div>{{end}}
<div class="alert {{if .CoverageOK}}ok{{else}}warn{{end}}">{{.Coverage}}</div>
{{if .ToolPlanHeader}}<div class="alert">{{.ToolPlanHeader}}.{{if .ToolPlan}}<ul>{{range .ToolPlan}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>{{end}}
{{if .Uncovered}}<div class="alert warn"><strong>Not covered by any scanner that ran:</strong> {{.Uncovered}}. Code in these languages was not analyzed, so no findings there is not evidence of safety.</div>{{end}}

<p class="lead" style="margin-top:20px">{{.Summary}}</p>
<div class="cards">
  <div class="card"><div class="n">{{.Total}}</div><div class="l">Findings</div></div>
  {{range .Counts}}<div class="card"><div class="n">{{.Count}}</div><div class="l"><span class="badge b-{{sev .Severity}}">{{sev .Severity}}</span></div></div>{{end}}
  {{if .Dismissed}}<div class="card"><div class="n">{{len .Dismissed}}</div><div class="l">Dismissed by AI</div></div>{{end}}
  {{if .Hardening}}<div class="card"><div class="n">{{len .Hardening}}</div><div class="l">Hardening notes</div></div>{{end}}
  {{if .Suppressed}}<div class="card"><div class="n">{{len .Suppressed}}</div><div class="l">Suppressed in code</div></div>{{end}}
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
      <span class="status s-{{.StatusClass}}">{{.Status}}</span>
      <span class="loc">{{.Location.File}}{{if .Location.Region.StartLine}}:{{.Location.Region.StartLine}}{{end}}</span></summary>
    <div class="body">
      <div class="msg">{{.Message}}</div>
      <div class="kv">Tool: {{.Tool}}{{if .CWE}} · {{range $i,$c := .CWE}}{{if $i}}, {{end}}{{$c}}{{end}}{{end}}{{if .Correlated}} · also reported by {{range $i,$c := .Correlated}}{{if $i}}, {{end}}{{$c}}{{end}}{{end}}</div>
      {{if .Secret}}<div class="kv">This looks like a credential, so the matched text is withheld. Rotate it, then remove it from history.</div>{{end}}
      {{if .Snippet}}<pre>{{.Snippet}}</pre>{{end}}
      {{with .Verdict}}
      <div class="kv" style="margin-top:8px"><span class="verdict">{{.Classification}} · {{printf "%.0f%%" (pct .Confidence)}}{{if .Exploitability}} · {{.Exploitability}}{{end}}{{if .Disputed}} · disputed by judge{{else if .Refuted}} · refuted{{else if .Overturned}} · overturned by judge{{end}}</span></div>
      {{if .Reasoning}}<div class="kv">{{.Reasoning}}</div>{{end}}
      {{end}}
      {{with .DetailRows}}<table class="gates">{{range .}}<tr><td>{{.Label}}</td><td colspan="2">{{.Text}}</td></tr>{{end}}</table>{{end}}
      {{if .PathRows}}<div class="kv"><strong>Path</strong> (traced by {{.PathSource}}):</div><ol class="path">{{range .PathRows}}<li><code>{{.}}</code></li>{{end}}</ol>{{end}}
      {{with .GateRows}}<table class="gates">{{range .}}<tr><td>{{.Question}}</td><td><strong>{{.Answer}}</strong></td><td>{{.Evidence}}</td></tr>{{end}}</table>{{end}}
      {{with .StabilityLine}}<div class="kv">{{.}}</div>{{end}}
      {{with .DeepLine}}<div class="kv">{{.}}</div>{{end}}
      {{if .VerdictFix}}<div class="fix"><h4>Suggested fix</h4><div>{{.VerdictFix}}</div></div>{{end}}
      {{with .FixLine}}<div class="kv">{{.}}</div>{{end}}
      {{with .Remediation}}
      <div class="fix">
        <h4>Suggested fix</h4>
        <div>{{.Summary}}</div>
        {{if .Guidance}}<div class="kv" style="margin-top:6px">{{.Guidance}}</div>{{end}}
        {{if .Diff}}<pre>{{.Diff}}</pre>{{end}}
      </div>
      {{end}}
      {{with .RegressionTestView}}
      <div class="fix">
        <h4>Proposed regression test{{if .File}} <span class="kv">for {{.File}}</span>{{end}}</h4>
        {{if .Description}}<div>{{.Description}}</div>{{end}}
        <pre>{{.Code}}</pre>
        <div class="kv">A model wrote this test and Achilles did not run it. Check it fails before the fix and passes after, then add it.</div>
      </div>
      {{end}}
    </div>
  </details>
  {{end}}
  {{else}}<div class="empty">{{if .Incomplete}}No findings from the tools that ran, but the scan is incomplete.{{else}}No findings. ✅{{end}}</div>{{end}}
</section>

{{if .Suppressed}}
<section>
  <h2>Suppressed by comments in the code <span class="tag">{{len .Suppressed}}</span></h2>
  <p class="lead">Each of these has an <code>achilles:ignore</code> comment beside it in the scanned code. They did not gate the build or open issues. The comment is the repository's own word about its finding: read the reason, especially where the change under review added it. Re-run with <code>--no-repo-config</code> to treat them as findings.</p>
  <div class="tbl-scroll"><table>
    <tr><th>Rule</th><th>Where</th><th>Reason given</th><th></th></tr>
    {{range .Suppressed}}
    <tr><td><span class="badge b-{{sev .Severity}}">{{sev .Severity}}</span> <span class="rule">{{.RuleID}}</span></td>
      <td>{{.Location.File}}{{if .Location.Region.StartLine}}:{{.Location.Region.StartLine}}{{end}}</td>
      <td>{{.Suppression.Reason}}</td>
      <td>{{if .Suppression.New}}<strong>added by this change</strong>{{end}}</td></tr>
    {{end}}
  </table></div>
</section>
{{end}}

{{if .Hardening}}
<section>
  <h2>Hardening notes <span class="tag">{{len .Hardening}}</span></h2>
  <p class="lead">The AI review judged each of these a real weakness that another control in the code already stops. They are not vulnerabilities and did not gate the build, but each is a layer of defense worth adding when the code is next touched. Re-run with <code>--keep-dismissed</code> to treat them as findings.</p>
  <div class="tbl-scroll"><table>
    <tr><th>Rule</th><th>Where</th><th>Confidence</th><th>What already stops it</th></tr>
    {{range .Hardening}}
    <tr><td><span class="badge b-{{sev .Severity}}">{{sev .Severity}}</span> <span class="rule">{{.RuleID}}</span></td>
      <td>{{.Location.File}}{{if .Location.Region.StartLine}}:{{.Location.Region.StartLine}}{{end}}</td>
      <td>{{with .Verdict}}{{printf "%.0f%%" (pct .Confidence)}}{{end}}</td>
      <td>{{with .Verdict}}{{.Reasoning}}{{end}}</td></tr>
    {{end}}
  </table></div>
</section>
{{end}}

{{if .Dismissed}}
<section>
  <h2>Ruled out by the AI review <span class="tag">{{len .Dismissed}}</span></h2>
  <p class="lead">These did not gate the build or open issues. Skim them: a wrong dismissal is the costly mistake. Re-run with <code>--keep-dismissed</code> to treat them as findings.</p>
  <div class="tbl-scroll"><table>
    <tr><th>Rule</th><th>Where</th><th>Confidence</th><th>Why</th></tr>
    {{range .Dismissed}}
    <tr><td><span class="badge b-{{sev .Severity}}">{{sev .Severity}}</span> <span class="rule">{{.RuleID}}</span></td>
      <td>{{.Location.File}}{{if .Location.Region.StartLine}}:{{.Location.Region.StartLine}}{{end}}</td>
      <td>{{with .Verdict}}{{printf "%.0f%%" (pct .Confidence)}}{{end}}</td>
      <td>{{with .Verdict}}{{if .RefuteReason}}{{.RefuteReason}}{{else}}{{.Reasoning}}{{end}}{{end}}</td></tr>
    {{end}}
  </table></div>
</section>
{{end}}

{{if .Hunted}}
<section>
  <h2>Hunt candidates the AI review did not confirm <span class="tag">{{len .Hunted}}</span></h2>
  <p class="lead">Hunt mode (<code>--hunt</code>) had the model follow the data from entry points and report what it could trace to a dangerous operation. The AI review did not confirm these, so they did not gate the build or open issues. They are leads, not findings: worth a look where the path is short.</p>
  <div class="tbl-scroll"><table>
    <tr><th>Class</th><th>Where</th><th>What the hunt claimed</th><th>Review</th></tr>
    {{range .Hunted}}
    <tr><td><span class="badge b-{{sev .Severity}}">{{sev .Severity}}</span> <span class="rule">{{.RuleID}}</span></td>
      <td>{{.Location.File}}{{if .Location.Region.StartLine}}:{{.Location.Region.StartLine}}{{end}}</td>
      <td>{{.Message}}{{if .PathRows}}<ol class="path">{{range .PathRows}}<li><code>{{.}}</code></li>{{end}}</ol>{{end}}</td>
      <td>{{.Status}}{{with .Verdict}} · {{printf "%.0f%%" (pct .Confidence)}}{{if .Reasoning}}: {{.Reasoning}}{{end}}{{end}}</td></tr>
    {{end}}
  </table></div>
</section>
{{end}}

<footer>Generated by Achilles · LLM-assisted SAST · AI verdicts are model judgments, not proof — review before acting on them.</footer>
</div></body></html>`

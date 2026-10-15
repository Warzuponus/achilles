package issues

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
)

const (
	// maxBody is the size we stay under. GitHub rejects bodies over 65536
	// characters; a margin keeps multi-byte text and the footer safe.
	maxBody     = 60000
	maxTitle    = 120
	maxMessage  = 2000
	maxReason   = 4000
	maxGuidance = 3000
	maxCode     = 1500
	maxDiff     = 20000
	maxListRows = 50
	maxRuleRows = 100
	maxRollRows = 150
)

// renderer turns units into issue titles and bodies.
type renderer struct {
	target string // scan target; stripped from paths and prose
	repo   string
	sha    string
	server string
	group  Group
}

func newRenderer(target string, o Options) *renderer {
	return &renderer{target: target, repo: o.Repo, sha: sanitizeKey(o.CommitSHA), server: o.ServerURL, group: o.Group}
}

// render returns the title and final body for a unit. The body carries a rev
// marker: a hash of the content rendered WITHOUT the commit SHA, so permalinks
// moving to a new commit do not by themselves count as a change.
func (r *renderer) render(u *unit) (title, body string) {
	title = r.title(u)

	stable := *r
	stable.sha = ""
	h, m, f := stable.build(u, "", true)
	sum := sha256.Sum256([]byte(h + m + f))
	rev := hex.EncodeToString(sum[:])[:12]

	head, mid, foot := r.build(u, rev, true)
	if len(head)+len(mid)+len(foot) > maxBody {
		// Cut the diff first.
		head, mid, foot = r.build(u, rev, false)
	}
	if over := len(head) + len(mid) + len(foot) - maxBody; over > 0 {
		const note = "\n\n_[truncated: this issue exceeded GitHub's size limit; run Achilles locally for the full report]_\n"
		keep := maxBody - len(head) - len(foot) - len(note)
		if keep < 0 {
			keep = 0
		}
		mid = cutUTF8(mid, keep) + note
	}
	return title, head + mid + foot
}

func (r *renderer) title(u *unit) string {
	var t string
	f := u.findings[0]
	file := r.relFile(f)
	sev := sevBadge(u.sev)
	switch r.group {
	case GroupRollup:
		t = fmt.Sprintf("Achilles: %d security finding(s) to review (%s)", len(u.findings), r.sevCounts(u.findings))
	case GroupRule:
		if len(u.findings) == 1 {
			t = fmt.Sprintf("[%s] %s in %s", sev, f.RuleID, file)
		} else {
			t = fmt.Sprintf("[%s] %s (%d locations)", sev, f.RuleID, len(u.findings))
		}
	default:
		t = fmt.Sprintf("[%s] %s in %s", sev, f.RuleID, file)
		if n := len(u.findings); n > 1 {
			t += fmt.Sprintf(" (+%d more)", n-1)
		}
	}
	t = strings.Join(strings.Fields(t), " ")
	t = redact.Prompt(t)
	if utf8.RuneCountInString(t) > maxTitle {
		rs := []rune(t)
		t = string(rs[:maxTitle-1]) + "…"
	}
	return t
}

func (r *renderer) sevCounts(fs []model.Finding) string {
	counts := map[model.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func sevBadge(s model.Severity) string { return strings.ToUpper(string(s)) }

const footer = "\n---\n_Managed by Achilles. To suppress this finding, close this issue: Achilles will not reopen an issue a human closed. " +
	"When a full scan no longer reports the finding, Achilles closes the issue itself, and reopens it if the finding comes back._\n"

// build assembles an issue body in three parts so the middle can be trimmed.
func (r *renderer) build(u *unit, rev string, withDiff bool) (head, mid, foot string) {
	head = "<!-- achilles:" + u.key + " -->\n"
	if rev != "" {
		head += "<!-- achilles:rev:" + rev + " -->\n"
	}
	switch r.group {
	case GroupRollup:
		mid = r.rollupMid(u)
	case GroupRule:
		mid = r.ruleMid(u, withDiff)
	default:
		mid = r.findingMid(u, withDiff)
	}
	return head, mid, footer
}

func (r *renderer) summaryLine(u *unit) string {
	f := u.findings[0]
	parts := []string{
		"**Severity:** `" + sevBadge(u.sev) + "`",
		"**Rule:** `" + r.inline(f.RuleID) + "`",
		"**Tool:** `" + r.inline(f.Tool) + "`",
	}
	if cwes := unionCWE(u.findings); len(cwes) > 0 {
		parts = append(parts, "**CWE:** "+r.inline(strings.Join(cwes, ", ")))
	}
	return strings.Join(parts, " · ") + "\n"
}

func (r *renderer) findingMid(u *unit, withDiff bool) string {
	var b strings.Builder
	b.WriteString(r.summaryLine(u))
	if len(u.findings) == 1 {
		fmt.Fprintf(&b, "\n**Location:** %s\n", r.link(u.findings[0]))
	} else {
		fmt.Fprintf(&b, "\n**Locations (%d)** share this fingerprint:\n\n", len(u.findings))
		for i, f := range u.findings {
			if i == maxListRows {
				fmt.Fprintf(&b, "- ... and %d more\n", len(u.findings)-maxListRows)
				break
			}
			fmt.Fprintf(&b, "- %s\n", r.link(f))
		}
	}
	r.writeDetail(&b, representative(u.findings), withDiff)
	return b.String()
}

func (r *renderer) ruleMid(u *unit, withDiff bool) string {
	var b strings.Builder
	b.WriteString(r.summaryLine(u))
	fmt.Fprintf(&b, "\n**Locations (%d):**\n\n| Severity | Location | Message |\n|---|---|---|\n", len(u.findings))
	for i, f := range u.findings {
		if i == maxRuleRows {
			fmt.Fprintf(&b, "| | ... and %d more | |\n", len(u.findings)-maxRuleRows)
			break
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", sevBadge(f.Severity), r.link(f), r.cell(f, 200))
	}
	rep := representative(u.findings)
	fmt.Fprintf(&b, "\n_The details below are for %s._\n", r.link(rep))
	r.writeDetail(&b, rep, withDiff)
	return b.String()
}

func (r *renderer) rollupMid(u *unit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%d finding(s):** %s\n\n| Severity | Rule | Location | Message |\n|---|---|---|---|\n",
		len(u.findings), r.sevCounts(u.findings))
	for i, f := range u.findings {
		if i == maxRollRows {
			fmt.Fprintf(&b, "| | | ... and %d more | |\n", len(u.findings)-maxRollRows)
			break
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", sevBadge(f.Severity), r.inline(f.RuleID), r.link(f), r.cell(f, 140))
	}
	return b.String()
}

// writeDetail writes the message, AI review and suggested fix for one finding.
// A secret-scanner finding gets generic rotation guidance instead: the matched
// text, code context, AI reasoning and any diff would repeat the secret.
func (r *renderer) writeDetail(b *strings.Builder, f model.Finding, withDiff bool) {
	if isSecretFinding(f) {
		b.WriteString("\n### Credential finding\n\n" +
			"This looks like a hard-coded credential. The matched value, surrounding code and automated analysis are deliberately **not** included in this issue.\n\n" +
			"Treat the credential as compromised: rotate or revoke it first, then remove it from the code and from git history, and load it from a secret manager or environment variable instead.\n")
		return
	}
	if msg := r.prose(f.Message, maxMessage); msg != "" {
		fmt.Fprintf(b, "\n%s\n", msg)
	}
	if code := strings.TrimSpace(f.CodeContext); code != "" {
		code = cutUTF8(redactCode(r.strip(code)), maxCode)
		fmt.Fprintf(b, "\n**Code**\n\n%s\n", fenced("", code))
	}
	if v := f.Verdict; v != nil {
		b.WriteString("\n### AI review\n\n")
		fmt.Fprintf(b, "- **Verdict:** %s (confidence %d%%)\n", strings.ReplaceAll(string(v.Classification), "_", " "), pct(v.Confidence))
		if v.Exploitability != "" {
			fmt.Fprintf(b, "- **Exploitability:** %s\n", strings.ReplaceAll(string(v.Exploitability), "_", " "))
		}
		if v.Overturned {
			b.WriteString("- **Note:** the first AI pass called this a false positive, but the adversarial pass found concrete evidence otherwise, so it is kept for a human to confirm.\n")
		}
		if v.Disputed() {
			b.WriteString("- **Note:** the adversarial pass disagreed with this verdict, but not strongly enough to rule the finding out, so it is kept for a human to confirm.\n")
		}
		if reason := r.prose(v.Reasoning, maxReason); reason != "" {
			fmt.Fprintf(b, "\n%s\n", reason)
		}
	}
	r.writeFix(b, f, withDiff)
}

func (r *renderer) writeFix(b *strings.Builder, f model.Finding, withDiff bool) {
	var parts []string
	if v := f.Verdict; v != nil {
		if s := r.prose(v.SuggestedFix, maxGuidance); s != "" {
			parts = append(parts, s)
		}
	}
	rem := f.Remediation
	if rem != nil {
		if s := r.prose(rem.Summary, maxGuidance); s != "" {
			parts = append(parts, s)
		}
		if s := r.prose(rem.Guidance, maxGuidance); s != "" {
			parts = append(parts, s)
		}
	}
	diff := ""
	if rem != nil {
		diff = strings.TrimSpace(rem.Diff)
	}
	if len(parts) == 0 && diff == "" {
		return
	}
	b.WriteString("\n### Suggested fix\n\n")
	if len(parts) > 0 {
		b.WriteString(strings.Join(parts, "\n\n") + "\n")
	}
	if rem != nil && rem.Confidence > 0 {
		fmt.Fprintf(b, "\n_Fix confidence: %d%%. Review before applying; Achilles proposes fixes but never applies them._\n", pct(rem.Confidence))
	}
	if line := r.verificationLine(rem, diff); line != "" {
		fmt.Fprintf(b, "\n%s\n", line)
	}
	switch {
	case diff == "":
	case !withDiff:
		b.WriteString("\n_The proposed diff was omitted because this issue would exceed GitHub's size limit (truncated)._\n")
	default:
		fmt.Fprintf(b, "\n%s\n", fenced("diff", cutLines(redactDiff(r.strip(diff)), maxDiff)))
	}
}

// verificationLine says whether re-scanning the proposed diff supported it. It
// only applies to a diff; prose guidance has nothing to verify. Empty when
// verification did not run.
func (r *renderer) verificationLine(rem *model.Remediation, diff string) string {
	if rem == nil || rem.Verification == nil || diff == "" {
		return ""
	}
	v := rem.Verification
	if v.Status == model.FixVerified {
		return "**Verified:** the scanner that reported this no longer reports it after applying this patch, and it reported nothing new. " +
			"That does not prove the change is correct or that the program still works; review and test it."
	}
	reasons := map[model.FixVerificationStatus]string{
		model.FixNotFixed:      "the scanner still reports this finding after applying the patch",
		model.FixIntroducesNew: "the scanner reports new findings after applying the patch",
		model.FixPatchFailed:   "the patch did not apply cleanly or was rejected as unsafe",
		model.FixSkipped:       "verification was skipped",
		model.FixError:         "verification could not complete",
	}
	reason := reasons[v.Status]
	if reason == "" {
		reason = "verification did not confirm this fix"
	}
	out := "**Not verified:** " + reason + "."
	if d := strings.Join(strings.Fields(r.prose(v.Detail, 300)), " "); d != "" {
		out += " " + d
	}
	if len(v.NewFindings) > 0 {
		var items []string
		for i, n := range v.NewFindings {
			if i == 5 {
				items = append(items, fmt.Sprintf("and %d more", len(v.NewFindings)-5))
				break
			}
			items = append(items, "`"+r.inline(r.strip(n))+"`")
		}
		out += " New: " + strings.Join(items, ", ") + "."
	}
	return out
}

// representative picks the finding whose details the issue shows: the first one
// that carries a fix, else a verdict, else the first.
func representative(fs []model.Finding) model.Finding {
	for _, f := range fs {
		if f.Remediation != nil || (f.Verdict != nil && f.Verdict.SuggestedFix != "") {
			return f
		}
	}
	for _, f := range fs {
		if f.Verdict != nil {
			return f
		}
	}
	return fs[0]
}

func unionCWE(fs []model.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		for _, c := range f.CWE {
			if c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

func pct(f float64) int {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 100
	}
	return int(f*100 + 0.5)
}

// ----- links and paths -----

func (r *renderer) relFile(f model.Finding) string {
	return relPath(r.target, f.Location.File)
}

// link renders file:line, as a permalink to the commit when one is known.
func (r *renderer) link(f model.Finding) string {
	rel := r.relFile(f)
	line := f.Location.Region.StartLine
	text := rel
	if text == "" {
		text = "(unknown file)"
	}
	if line > 0 {
		text = fmt.Sprintf("%s:%d", text, line)
	}
	text = redact.Prompt(strings.ReplaceAll(text, "`", ""))
	if r.sha == "" || r.repo == "" || rel == "" {
		return "`" + text + "`"
	}
	segs := strings.Split(rel, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	// A finding made in the git history links to the file as it was in that commit:
	// at the scanned commit the line may not exist any more.
	sha := r.sha
	if f.Commit != "" {
		sha = sanitizeKey(f.Commit)
	}
	u := fmt.Sprintf("%s/%s/blob/%s/%s", r.server, r.repo, sha, strings.Join(segs, "/"))
	if line > 0 {
		u += fmt.Sprintf("#L%d", line)
		if end := f.Location.Region.EndLine; end > line {
			u += fmt.Sprintf("-L%d", end)
		}
	}
	return "[`" + text + "`](" + u + ")"
}

// relPath makes a finding's file repo-relative: it strips the scan target and a
// file:// scheme, and never returns an absolute or parent-escaping path (an
// absolute path outside the target is reduced to its base name) so local
// directory layouts do not leak into an issue.
func relPath(target, file string) string {
	f := filepath.ToSlash(strings.TrimPrefix(file, "file://"))
	if target != "" {
		t := filepath.ToSlash(filepath.Clean(target))
		if f == t {
			f = path.Base(f)
		} else if strings.HasPrefix(f, t+"/") {
			f = f[len(t)+1:]
		}
	}
	f = path.Clean(f)
	if f == "." {
		return ""
	}
	if path.IsAbs(f) || f == ".." || strings.HasPrefix(f, "../") || (len(f) > 1 && f[1] == ':') {
		f = path.Base(f)
	}
	return f
}

// ----- text hygiene -----

var mentionRE = regexp.MustCompile(`@([A-Za-z0-9])`)

// strip removes the scan target's absolute path from text.
func (r *renderer) strip(s string) string {
	t := filepath.ToSlash(filepath.Clean(r.target))
	if r.target == "" || len(t) < 2 {
		return s
	}
	s = strings.ReplaceAll(s, t+"/", "")
	return strings.ReplaceAll(s, t, ".")
}

// prose prepares free text (a tool message, AI reasoning, guidance) for an issue:
// secrets masked, local paths removed, HTML comments and @mentions defused, and
// the result bounded. Findings come from scanning untrusted code, so their text
// is untrusted too.
func (r *renderer) prose(s string, limit int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = redact.Secrets(r.strip(s))
	s = strings.ReplaceAll(s, "<!--", "&lt;!--")
	s = mentionRE.ReplaceAllString(s, "@\u200b$1")
	if len(s) > limit {
		s = cutUTF8(s, limit) + " ... (truncated)"
	}
	return s
}

// inline sanitizes a short value for a Markdown code span.
func (r *renderer) inline(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "`", "'")), " ")
	return redact.Prompt(s)
}

// cell renders a finding's message for a table cell.
func (r *renderer) cell(f model.Finding, limit int) string {
	if isSecretFinding(f) {
		return "_(credential: details withheld)_"
	}
	s := r.prose(f.Message, limit)
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}

// redactCode masks secrets in code but leaves file paths in diff headers alone.
func redactCode(s string) string { return redact.Secrets(s) }

func redactDiff(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "+++ ") || strings.HasPrefix(l, "@@") || strings.HasPrefix(l, "diff ") {
			lines[i] = redact.Prompt(l)
		} else {
			lines[i] = redact.Secrets(l)
		}
	}
	return strings.Join(lines, "\n")
}

// fenced wraps content in a code fence longer than any backtick run inside it, so
// the content cannot close the fence and inject Markdown.
func fenced(lang, content string) string {
	longest, run := 0, 0
	for _, c := range content {
		if c == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + lang + "\n" + content + "\n" + fence
}

// cutUTF8 shortens s to at most n bytes without splitting a rune.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cutLines shortens s to at most n bytes at a line boundary, noting the cut.
func cutLines(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = cutUTF8(s, n)
	if i := strings.LastIndex(s, "\n"); i > 0 {
		s = s[:i]
	}
	return s + "\n... (diff truncated)"
}

// ----- secrets -----

var secretRuleRE = regexp.MustCompile(`(?i)secret|key|token|passw|credential`)

// secretCWEs are the "hard-coded / plaintext credential" weaknesses.
var secretCWEs = map[string]bool{"798": true, "259": true, "321": true, "256": true}

// isSecretFinding reports whether a finding is (or may be) about a leaked
// credential. It errs toward true: wrongly withholding detail costs a click,
// wrongly publishing a secret is unrecoverable.
func isSecretFinding(f model.Finding) bool {
	if strings.EqualFold(f.Tool, "gitleaks") || secretRuleRE.MatchString(f.RuleID) {
		return true
	}
	for _, c := range f.CWE {
		if secretCWEs[strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CWE-")] {
			return true
		}
	}
	return false
}

// ----- comments -----

func (r *renderer) resolvedComment() string {
	return "<!-- achilles:resolved -->\nResolved: Achilles no longer detects this finding in a full scan. Closing automatically. " +
		"If the finding comes back, this issue will be reopened."
}

func (r *renderer) reopenComment() string {
	at := ""
	if r.sha != "" {
		short := r.sha
		if len(short) > 7 {
			short = short[:7]
		}
		at = " at commit `" + short + "`"
	}
	return "Reopened: Achilles detects this finding again" + at + ". It had been closed automatically. " +
		"If you intend to ignore it, close this issue again and Achilles will leave it closed."
}

// suppressedComment closes an issue whose finding now has a suppression comment
// beside it. It says so, and quotes the reason: closing it as "resolved" would
// claim a fix nobody made.
func (r *renderer) suppressedComment(f model.Finding) string {
	sup := f.Suppression
	var b strings.Builder
	b.WriteString("<!-- achilles:resolved -->\nClosing: this finding is now suppressed by an `achilles:ignore` comment in the code")
	if sup != nil {
		fmt.Fprintf(&b, " (`%s:%d`)", strings.ReplaceAll(redact.Prompt(relPath(r.target, sup.File)), "`", ""), sup.Line)
		if reason := r.prose(sup.Reason, maxReason); reason != "" {
			b.WriteString(". The reason given there:\n\n" + reason)
		}
	}
	b.WriteString("\n\nIt was not fixed. If the comment is removed and the finding is reported again, this issue will be reopened.")
	return b.String()
}

func (r *renderer) dismissedComment(f model.Finding) string {
	var b strings.Builder
	b.WriteString("<!-- achilles:resolved -->\nClosing: the AI review now judges this finding a false positive")
	if v := f.Verdict; v != nil {
		fmt.Fprintf(&b, " (confidence %d%%)", pct(v.Confidence))
		if !isSecretFinding(f) {
			why := v.Reasoning
			if v.Refuted && v.RefuteReason != "" {
				why = v.RefuteReason
			}
			if reason := r.prose(why, maxReason); reason != "" {
				b.WriteString(".\n\n" + reason)
			}
		}
	}
	b.WriteString("\n\nIf it is reported again as a real issue, this issue will be reopened.")
	return b.String()
}

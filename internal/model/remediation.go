package model

import (
	"path"
	"strings"
	"unicode/utf8"
)

// Remediation is the fix proposal for a confirmed finding. We propose; we never
// auto-apply (DESIGN.md §1 Non-Goals). Diff is set when a concrete, local patch
// is possible; Guidance carries prose when the fix needs human judgment.
type Remediation struct {
	Summary    string  `json:"summary"`
	Diff       string  `json:"diff,omitempty"`
	Guidance   string  `json:"guidance,omitempty"`
	Confidence float64 `json:"confidence"`

	// Verification is the result of re-scanning the patch (--verify-fixes); nil when
	// verification did not run. See docs/verifying-fixes.md for what it proves.
	Verification *FixVerification `json:"verification,omitempty"`

	// ReusedFrom is the run this proposal was first made in, when it was taken from
	// the cache instead of asked for again: the same finding, code, position, fix
	// hint, prompt and model. Empty for a proposal made in this run. A model can
	// never set it.
	ReusedFrom string `json:"reusedFrom,omitempty"`

	// RegressionTest is a test the model proposes alongside the fix: one that
	// should fail before it and pass after. Achilles never runs it and never
	// commits it; it is shown for a developer to adapt and add. Nil when the
	// model could not write one without guessing at code it was not shown.
	RegressionTest *RegressionTest `json:"regressionTest,omitempty"`
}

// RegressionTest is a proposed test for a fix.
type RegressionTest struct {
	File        string `json:"file"`                  // where the model suggests it goes, relative to the repository
	Code        string `json:"code"`                  // the test itself
	Description string `json:"description,omitempty"` // what it proves
}

// Limits on a proposed regression test, so one reply cannot fill a report.
const (
	MaxRegressionTestCode = 6000
)

// NormalizeRegressionTest bounds a model-written test and drops one that is
// empty or names a path outside the repository (absolute, or climbing out with
// ".."). The path is only a suggestion, but it is shown as one, so it must at
// least be a plausible place in the repository.
func (r *Remediation) NormalizeRegressionTest() {
	t := r.RegressionTest
	if t == nil {
		return
	}
	t.Code = strings.TrimRight(t.Code, " \t\n")
	file := strings.ReplaceAll(strings.TrimSpace(t.File), `\`, "/")
	if file != "" {
		file = path.Clean(file)
		if path.IsAbs(file) || file == ".." || strings.HasPrefix(file, "../") || strings.ContainsAny(file, "\x00\n\r") {
			file = ""
		}
	}
	t.File = cutUTF8(strings.TrimPrefix(file, "./"), 200)
	t.Description = boundDetail(t.Description)
	if strings.TrimSpace(t.Code) == "" {
		r.RegressionTest = nil
		return
	}
	if len(t.Code) > MaxRegressionTestCode {
		t.Code = cutUTF8(t.Code, MaxRegressionTestCode) + "\n… (truncated)"
	}
}

// FixVerificationStatus is the outcome of re-scanning a proposed patch.
type FixVerificationStatus string

const (
	// FixVerified: the patch applied in a temporary copy, the scanner that reported
	// the finding no longer reports it, and that scanner reported nothing new.
	FixVerified FixVerificationStatus = "verified"
	// FixNotFixed: the patch applied, but the scanner still reports the finding.
	FixNotFixed FixVerificationStatus = "not_fixed"
	// FixIntroducesNew: the finding is gone but the scanner reports something new.
	FixIntroducesNew FixVerificationStatus = "introduces_new"
	// FixPatchFailed: the diff was rejected as unsafe or did not apply cleanly.
	FixPatchFailed FixVerificationStatus = "patch_failed"
	// FixSkipped: verification was not attempted (target too large, scanner not
	// available). Says nothing about the patch.
	FixSkipped FixVerificationStatus = "skipped"
	// FixError: verification was attempted but the re-scan itself failed.
	FixError FixVerificationStatus = "error"
)

// FixVerification records how a proposed diff fared when its finding's scanner was
// re-run against a patched copy of the target.
type FixVerification struct {
	Status      FixVerificationStatus `json:"status"`
	Detail      string                `json:"detail,omitempty"`
	NewFindings []string              `json:"newFindings,omitempty"` // "rule file:line" of findings the patch introduced
}

// IsVerified reports whether the remediation carries a diff that a re-scan proved
// removes its finding without introducing new ones.
func (r *Remediation) IsVerified() bool {
	return r != nil && r.Verification != nil && r.Verification.Status == FixVerified
}

// cutUTF8 shortens s to at most n bytes without splitting a character.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

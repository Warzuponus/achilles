package triage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// Fix proposals are cached like verdicts (see cache.go), with two differences.
//
// The key keeps the line numbers. A verdict about a piece of code is the same
// wherever in the file the code sits, but a proposal usually carries a diff, and a
// diff is written against lines: if the code moved, the proposal is asked for again
// rather than reused on the hope that the patch still applies.
//
// What is cached is the proposal alone. Whether the patch works is not: the
// re-scan that verifies it runs again in every scan, against the code as it is.
//
// Signing matters more here than for verdicts. A cached proposal is a patch that
// is shown as a suggested fix and, with --fix-pr, applied to a branch, so an entry
// planted in a vault file that arrived with the repository would be a way to have
// Achilles propose the attacker's change. Entries are signed with the same secret
// as cached verdicts, which is kept outside any repository; an entry that does not
// verify is ignored.

// remediationEntry is the payload of a KindRemediationCache record.
type remediationEntry struct {
	Key         string            `json:"key"`
	Remediation model.Remediation `json:"remediation"`
	Sig         string            `json:"sig"`
}

// SetRemediationCacheScope turns on the cache for fix proposals. scope names what
// writes them (endpoint and model); a proposal is never reused across scopes. It
// has no effect unless SetVerdictCache has turned the cache on: the two share the
// age limit and the signing secret.
func (e *Engine) SetRemediationCacheScope(scope string) *Engine {
	if e.cache != nil {
		e.cache.remediationScope = scope
	}
	return e
}

func (e *Engine) cachesRemediations() bool {
	return e.cache != nil && e.cache.remediationScope != ""
}

// signRemediation is the entry's signature. The leading label keeps it from ever
// being equal to the signature of a cached verdict.
func (c *verdictCache) signRemediation(entry remediationEntry) string {
	r, _ := json.Marshal(entry.Remediation)
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte("remediation\x00"))
	mac.Write([]byte(entry.Key))
	mac.Write([]byte{0})
	mac.Write(r)
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *verdictCache) genuineRemediation(entry remediationEntry) bool {
	want, err := hex.DecodeString(c.signRemediation(entry))
	got, err2 := hex.DecodeString(entry.Sig)
	return err == nil && err2 == nil && hmac.Equal(want, got)
}

// remediationKey hashes everything the fix prompt is built from.
func (e *Engine) remediationKey(pf model.Finding, codeContext string) string {
	hint := ""
	if pf.Verdict != nil {
		hint = pf.Verdict.SuggestedFix
	}
	in := struct {
		Prompt  string `json:"prompt"`
		Scope   string `json:"scope"`
		NoCode  bool   `json:"noCode"`
		Tool    string `json:"tool"`
		Rule    string `json:"rule"`
		Message string `json:"message"`
		File    string `json:"file"`
		Line    int    `json:"line"`
		Hint    string `json:"hint"`
		Code    string `json:"code"` // with its line-number margin: position is part of the question
	}{
		Prompt: RemediationPromptVersion, Scope: e.cache.remediationScope, NoCode: e.noCode,
		Tool: pf.Tool, Rule: pf.RuleID, Message: pf.Message,
		File: pf.Location.File, Line: pf.Location.Region.StartLine, Hint: hint, Code: codeContext,
	}
	b, _ := json.Marshal(in)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// remediationFromCache looks for an earlier proposal made from the same prompt
// and, if there is a genuine one, applies it to f and reports true.
func (e *Engine) remediationFromCache(runID string, f *model.Finding, key string) bool {
	cutoff := e.cache.now().Add(-e.cache.maxAge)
	recs := e.vault.ByFingerprint(f.Fingerprint)
	for i := len(recs) - 1; i >= 0; i-- { // newest first
		rec := recs[i]
		if rec.Kind != vault.KindRemediationCache || rec.Timestamp.Before(cutoff) {
			continue
		}
		var entry remediationEntry
		if json.Unmarshal(rec.Payload, &entry) != nil || entry.Key != key || !e.cache.genuineRemediation(entry) {
			continue
		}
		r := entry.Remediation
		r.Verification = nil // never cached, and never taken from an entry
		r.ReusedFrom = rec.RunID
		if r.ReusedFrom == "" {
			r.ReusedFrom = "an earlier run"
		}
		f.Remediation = &r
		// This run's own record of the proposal, so the run is complete on its own.
		e.record(runID, vault.KindRemediation, "cache", f.Fingerprint, r)
		return true
	}
	return false
}

// rememberRemediation stores a model-written proposal for reuse.
func (e *Engine) rememberRemediation(runID string, f model.Finding, key string) {
	if f.Remediation == nil {
		return
	}
	r := *f.Remediation
	r.Verification, r.ReusedFrom = nil, ""
	entry := remediationEntry{Key: key, Remediation: r}
	entry.Sig = e.cache.signRemediation(entry)
	e.record(runID, vault.KindRemediationCache, "remediation", f.Fingerprint, entry)
}

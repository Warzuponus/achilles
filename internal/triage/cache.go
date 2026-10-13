package triage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// The verdict cache reuses a verdict when the same question has been answered
// before.
//
// Most of a repeat scan is findings that have not changed: the same rule on the
// same code, reviewed by the same models with the same prompt. Asking again costs
// two model calls per finding and, because models are not deterministic, can
// return a different answer for an unchanged input, which is how a finding flips
// between runs with nobody having touched it.
//
// A cached verdict is used only when everything the model would be shown is the
// same: the prompt version, the models and endpoint (the scope), the privacy mode,
// the sample count, the rule, severity, CWEs and message, the code around the
// finding, and any retrieved examples. Line numbers are left out of the
// comparison, so code that merely moved within its file still matches. Anything
// else differing is a miss, and the finding is reviewed afresh.
//
// The cache lives in the Evidence Vault, as records beside the verdicts
// themselves, so it needs no storage of its own.
//
// Every entry is signed. The vault's default location is inside the directory
// being scanned, so a vault file can arrive with the repository: a pull request
// could commit one holding a "false positive" entry for its own vulnerable code,
// with a correctly computed key, and have that code dismissed without any review.
// An entry therefore counts only if it carries an HMAC made with a secret that is
// kept outside any repository (the caller supplies it; the CLI keeps it in the
// Achilles home directory). A forged, altered or unsigned entry is ignored and the
// finding is reviewed as usual.

// cacheEntry is the payload of a KindVerdictCache record.
type cacheEntry struct {
	Key        string           `json:"key"`
	Verdict    model.Verdict    `json:"verdict"`
	Provenance model.Provenance `json:"provenance"`
	Sig        string           `json:"sig"`
}

type verdictCache struct {
	scope  string
	maxAge time.Duration
	secret []byte
	now    func() time.Time
	// remediationScope is the scope for cached fix proposals; empty leaves that
	// cache off (see cache_remediation.go).
	remediationScope string
}

// SetVerdictCache turns the verdict cache on. scope identifies what produces the
// verdicts (endpoint and models): a verdict is never reused across scopes. A
// verdict older than maxAge is not reused, since a provider can change the model
// behind a name. secret signs and verifies entries and must not be stored where a
// scanned repository could supply it; without one the cache stays off. now is the
// clock (nil: time.Now).
func (e *Engine) SetVerdictCache(scope string, maxAge time.Duration, secret []byte, now func() time.Time) *Engine {
	if maxAge <= 0 || e.vault == nil || len(secret) < 16 {
		e.cache = nil
		return e
	}
	if now == nil {
		now = time.Now
	}
	e.cache = &verdictCache{scope: scope, maxAge: maxAge, secret: secret, now: now}
	return e
}

// sign returns the entry's signature: an HMAC over the key and the exact verdict
// and provenance it vouches for.
func (c *verdictCache) sign(entry cacheEntry) string {
	v, _ := json.Marshal(entry.Verdict)
	p, _ := json.Marshal(entry.Provenance)
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(entry.Key))
	mac.Write([]byte{0})
	mac.Write(v)
	mac.Write([]byte{0})
	mac.Write(p)
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *verdictCache) genuine(entry cacheEntry) bool {
	want, err := hex.DecodeString(c.sign(entry))
	got, err2 := hex.DecodeString(entry.Sig)
	return err == nil && err2 == nil && hmac.Equal(want, got)
}

// cacheKey hashes everything the model would be shown for this finding.
func (e *Engine) cacheKey(pf model.Finding, codeContext string, examples []string) string {
	var code []string
	for _, line := range strings.Split(codeContext, "\n") {
		code = append(code, contextGutter.ReplaceAllString(line, ""))
	}
	in := struct {
		Prompt   string   `json:"prompt"`
		Scope    string   `json:"scope"`
		NoCode   bool     `json:"noCode"`
		Samples  int      `json:"samples"`
		Tool     string   `json:"tool"`
		Rule     string   `json:"rule"`
		Severity string   `json:"severity"`
		CWE      []string `json:"cwe"`
		Message  string   `json:"message"`
		File     string   `json:"file"`
		Code     []string `json:"code"`
		Examples []string `json:"examples"`
	}{
		Prompt: PromptVersion, Scope: e.cache.scope, NoCode: e.noCode, Samples: e.Samples(),
		Tool: pf.Tool, Rule: pf.RuleID, Severity: string(pf.Severity), CWE: pf.CWE, Message: pf.Message,
		File: pf.Location.File, Code: code, Examples: examples,
	}
	b, _ := json.Marshal(in)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fromCache looks for an earlier verdict on the same question and, if there is
// one, applies it to f and reports true.
func (e *Engine) fromCache(runID string, f *model.Finding, key string) bool {
	cutoff := e.cache.now().Add(-e.cache.maxAge)
	recs := e.vault.ByFingerprint(f.Fingerprint)
	for i := len(recs) - 1; i >= 0; i-- { // newest first
		rec := recs[i]
		if rec.Kind != vault.KindVerdictCache || rec.Timestamp.Before(cutoff) {
			continue
		}
		var entry cacheEntry
		if json.Unmarshal(rec.Payload, &entry) != nil || entry.Key != key || !e.cache.genuine(entry) {
			continue
		}
		v := entry.Verdict
		p := entry.Provenance
		p.ReusedFrom = rec.RunID
		if p.ReusedFrom == "" {
			p.ReusedFrom = "an earlier run"
		}
		f.Verdict, f.Provenance = &v, &p
		// This run's own record of the verdict, so the run is complete on its own.
		e.record(runID, vault.KindVerdict, "cache", f.Fingerprint, v)
		return true
	}
	return false
}

// remember stores a model-produced verdict for reuse.
func (e *Engine) remember(runID string, f model.Finding, key string) {
	if f.Verdict == nil || f.Provenance == nil {
		return
	}
	entry := cacheEntry{Key: key, Verdict: *f.Verdict, Provenance: *f.Provenance}
	entry.Sig = e.cache.sign(entry)
	e.record(runID, vault.KindVerdictCache, "triage", f.Fingerprint, entry)
}

// CacheScope builds the scope string for SetVerdictCache from what determines a
// verdict besides the prompt: where the calls go and which models answer.
func CacheScope(baseURL, triageModel, judgeModel string) string {
	return fmt.Sprintf("%s|triage=%s|judge=%s", strings.TrimRight(baseURL, "/"), triageModel, judgeModel)
}

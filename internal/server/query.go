package server

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// RunInfo summarizes a scan run for the dashboard.
type RunInfo struct {
	RunID    string    `json:"runId"`
	Target   string    `json:"target"`
	Mode     string    `json:"mode"`
	When     time.Time `json:"when"`
	Findings int       `json:"findings"`
}

// ListRuns returns runs newest-first, derived from scan_meta + finding records.
func ListRuns(v vault.Store) []RunInfo {
	byRun := map[string]*RunInfo{}
	for _, r := range v.All() {
		info := byRun[r.RunID]
		if info == nil {
			info = &RunInfo{RunID: r.RunID, When: r.Timestamp}
			byRun[r.RunID] = info
		}
		switch r.Kind {
		case vault.KindScanMeta:
			var meta struct {
				Target string `json:"target"`
				Mode   string `json:"mode"`
			}
			if json.Unmarshal(r.Payload, &meta) == nil {
				info.Target, info.Mode = meta.Target, meta.Mode
			}
		case vault.KindFinding:
			info.Findings++
		}
	}
	out := make([]RunInfo, 0, len(byRun))
	for _, info := range byRun {
		out = append(out, *info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.After(out[j].When) })
	return out
}

// RunFindings reconstructs a run's findings with their latest verdict attached,
// and redacts secret material before returning (DESIGN.md §10).
func RunFindings(v vault.Store, runID string) []model.Finding {
	var findings []model.Finding
	latestVerdict := map[string]model.Verdict{}

	for _, r := range v.ByRun(runID) {
		switch r.Kind {
		case vault.KindFinding:
			var f model.Finding
			if json.Unmarshal(r.Payload, &f) == nil {
				findings = append(findings, f)
			}
		case vault.KindVerdict:
			var vd model.Verdict
			if r.Fingerprint != "" && json.Unmarshal(r.Payload, &vd) == nil {
				latestVerdict[r.Fingerprint] = vd // later records overwrite earlier
			}
		}
	}

	for i := range findings {
		f := &findings[i]
		if vd, ok := latestVerdict[f.Fingerprint]; ok {
			v := vd
			f.Verdict = &v
		}
		redactFinding(f)
	}
	return findings
}

// withheldNote stands in for the matched text of a credential finding.
const withheldNote = "[withheld: this finding is a credential, so its matched text is not shown]"

// redactFinding removes secret material from a finding before it is served.
//
// A credential finding's snippet IS the secret, and a pattern mask cannot be
// trusted to recognise every key shape, so that snippet is withheld outright (the
// HTML report and the issue renderer do the same). Everything else that can quote
// repository text — the message, the code context, and what the model wrote about
// it — goes through the pattern mask.
func redactFinding(f *model.Finding) {
	f.Message = Redact(f.Message)
	if f.IsSecret() {
		if f.CodeContext != "" {
			f.CodeContext = withheldNote
		}
	} else {
		f.CodeContext = Redact(f.CodeContext)
	}
	if v := f.Verdict; v != nil {
		v.Reasoning, v.SuggestedFix = Redact(v.Reasoning), Redact(v.SuggestedFix)
		v.RefuteReason, v.RefuteEvidence = Redact(v.RefuteReason), Redact(v.RefuteEvidence)
	}
	if r := f.Remediation; r != nil {
		r.Summary, r.Diff, r.Guidance = Redact(r.Summary), Redact(r.Diff), Redact(r.Guidance)
	}
}

// AuditRecords returns a run's vault records (the audit trail) with secret
// material removed. The vault on disk is the complete record; this is the copy
// that is safe to serve to whoever can reach the War Room.
//
//   - raw scanner output is not served at all. It is the scanners' unfiltered
//     view of the repository (a secret scanner's report is a list of secrets), and
//     nothing in the UI needs it. The record is kept, with its size, so the trail
//     still shows that the tool ran and when.
//   - a finding record is redacted the same way the run page redacts it.
//   - every other payload (LLM prompts and replies, verdicts, remediations,
//     reviews) has each string value passed through the pattern mask.
func AuditRecords(v vault.Store, runID string) []vault.Record {
	recs := v.ByRun(runID)
	out := make([]vault.Record, len(recs))
	for i, r := range recs {
		r.Payload = redactPayload(r.Kind, r.Payload)
		out[i] = r
	}
	return out
}

func redactPayload(kind vault.Kind, payload json.RawMessage) json.RawMessage {
	if len(payload) == 0 {
		return payload
	}
	withheld := func(why string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"withheld": why, "bytes": len(payload)})
		return b
	}
	switch kind {
	case vault.KindRawOutput:
		return withheld("raw scanner output is not served by the War Room; read it from the Evidence Vault on the machine that ran the scan")
	case vault.KindFinding:
		var f model.Finding
		if err := json.Unmarshal(payload, &f); err != nil {
			return withheld("unreadable finding record")
		}
		redactFinding(&f)
		if b, err := json.Marshal(f); err == nil {
			return b
		}
		return withheld("unreadable finding record")
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		// Not JSON we can walk: serving it unredacted is the one thing we must not do.
		return withheld("unreadable record")
	}
	b, err := json.Marshal(redactValue("", doc))
	if err != nil {
		return withheld("unreadable record")
	}
	return b
}

// identifierKeys hold ids that link records together. They are hashes, which the
// long-token mask would otherwise blank, breaking the trail without hiding a secret.
var identifierKeys = map[string]bool{
	"id": true, "fingerprint": true, "runId": true, "prevId": true, "correlatedFrom": true, "sourceCommit": true,
}

// redactValue masks every string in a decoded JSON value, at any depth.
func redactValue(key string, v any) any {
	switch t := v.(type) {
	case string:
		if identifierKeys[key] {
			return t
		}
		return Redact(t)
	case []any:
		for i := range t {
			t[i] = redactValue(key, t[i])
		}
		return t
	case map[string]any:
		for k, val := range t {
			t[k] = redactValue(k, val)
		}
		return t
	}
	return v
}

// RedactFinding removes secret material from a finding the way the War Room does
// before serving it, for other readers of the vault that hand findings to someone
// (the MCP server).
func RedactFinding(f *model.Finding) { redactFinding(f) }

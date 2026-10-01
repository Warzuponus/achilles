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
		f.Message = Redact(f.Message)
		f.CodeContext = Redact(f.CodeContext)
	}
	return findings
}

// AuditRecords returns the raw vault records for a run (the audit trail).
func AuditRecords(v vault.Store, runID string) []vault.Record {
	return v.ByRun(runID)
}

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/suppress"
	"github.com/Warzuponus/achilles/internal/vault"
	"github.com/Warzuponus/achilles/internal/vcs"
)

// applySuppressions honours `achilles:ignore RULE -- reason` comments in the
// scanned code: a finding with one beside it moves from scan.Findings to
// scan.Suppressed, so it does not gate, is not sent to the model and files no
// issue, and every report lists it with the reason the comment gives.
//
// The comments are the repository's own word about its findings, so the policy is
// the one for the rest of its configuration:
//
//   - never silent: the count is printed, and each one is in the reports;
//   - with --diff, a comment on a line the change itself added or edited is
//     called out, on stderr and at the top of the reports, like a change to a
//     scanner's ignore file;
//   - with --no-repo-config none is honoured, and the number that would have been
//     is printed.
//
// It runs after the baseline, so a finding the baseline already accounts for is
// not also listed as suppressed.
func applySuppressions(o *options, ev vault.Store, runID, absTarget string, scan *model.Scan, warn io.Writer) {
	found := suppress.Find(absTarget, scan.Findings)
	for _, p := range found.Problems {
		fmt.Fprintf(warn, "achilles: %s:%d: an %s comment was not honoured: %s\n", p.File, p.Line, suppress.Token, p.Why)
	}
	if len(found.Markers) == 0 {
		return
	}
	if o.noRepoConfig {
		fmt.Fprintf(warn, "achilles: --no-repo-config: %d %s comment(s) in the scanned code were not honoured; those findings are reported as usual\n",
			len(found.Markers), suppress.Token)
		return
	}

	added := map[string]map[int]bool{} // file -> lines the change under review touched
	whole := map[string]bool{}
	isNew := func(file string, line int) bool {
		if o.diffRef == "" {
			return false
		}
		if _, seen := added[file]; !seen {
			added[file], whole[file] = vcs.AddedLines(absTarget, o.diffRef, file)
		}
		return whole[file] || added[file][line]
	}

	kept := scan.Findings[:0:0]
	var fresh []string
	type entry struct {
		Fingerprint string `json:"fingerprint"`
		RuleID      string `json:"ruleId"`
		File        string `json:"file"`
		Line        int    `json:"line"`
		Reason      string `json:"reason"`
		New         bool   `json:"new,omitempty"`
	}
	var entries []entry
	for i, f := range scan.Findings {
		m, ok := found.Markers[i]
		if !ok {
			kept = append(kept, f)
			continue
		}
		sup := &model.Suppression{File: f.Location.File, Line: m.Line, Reason: m.Reason, New: isNew(f.Location.File, m.Line)}
		f.Suppression = sup
		scan.Suppressed = append(scan.Suppressed, f)
		entries = append(entries, entry{f.Fingerprint, f.RuleID, sup.File, sup.Line, sup.Reason, sup.New})
		if sup.New {
			fresh = append(fresh, fmt.Sprintf("suppression: %s:%d", sup.File, sup.Line))
		}
	}
	scan.Findings = kept

	fmt.Fprintf(warn, "achilles: %d finding(s) suppressed by %s comments in the scanned code; they are listed in the reports with the reasons given (--no-repo-config to refuse them)\n",
		len(scan.Suppressed), suppress.Token)
	if len(fresh) > 0 {
		scan.RepoConfigChanged = append(scan.RepoConfigChanged, fresh...)
		fmt.Fprintf(warn, "achilles: WARNING: this change adds or edits %d suppression comment(s) (%s). It is suppressing findings in itself; review each reason as part of this scan.\n",
			len(fresh), strings.Join(fresh, "; "))
	}
	recordJSON(ev, vault.Record{RunID: runID, Phase: "scan", Kind: vault.KindScanMeta, Source: "suppress"},
		map[string]any{"suppressed": entries})
}

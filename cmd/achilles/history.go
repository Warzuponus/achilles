package main

import (
	"fmt"
	"io"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vcs"
)

// --secrets-history scans the commits as well as the files. A credential that was
// committed and deleted a commit later is not in any file, so a scan of the files
// reports nothing, but it is in every clone and every fork. The registry tool
// marked `optIn: secrets-history` (gitleaks in its git mode) does the scanning.
//
// The scanner cannot be trusted to say when it could not do its job: outside a
// repository, on a checkout git refuses to read, or with a commit range that does
// not resolve, it logs a line, exits 0 and writes a report with no findings. So
// what can be checked beforehand is checked here, and what cannot is caught by
// the tool's incompleteWhen phrase. A history scan that did not cover the history
// is reported as failed or incomplete, never as clean.

const optInSecretsHistory = "secrets-history"

// optedIn reports whether the feature a registry tool is opt-in for was asked for.
func (o *options) optedIn(feature string) bool {
	return feature == optInSecretsHistory && o.secretsHistory
}

// planHistoryScan checks, before any scanner runs, that the history can be
// scanned. When it cannot be, the history scanner is not run at all and a failure
// is returned for it; when it can be but will not cover everything, the scanner
// runs and is reported as incomplete.
func planHistoryScan(o *options, cfg *config.Config, absTarget string, warn io.Writer) []toolDiag {
	if !o.secretsHistory {
		return nil
	}
	var tools []string
	for _, tc := range cfg.Tools {
		if tc.OptIn == optInSecretsHistory {
			tools = append(tools, tc.ID)
		}
	}
	if len(tools) == 0 {
		tools = []string{optInSecretsHistory} // a registry without one: still a failure, by the feature's name
	}
	var diags []toolDiag
	report := func(stage, msg string) {
		for _, id := range tools {
			diags = append(diags, toolDiag{Tool: id, Stage: stage, Error: msg})
			fmt.Fprintf(warn, "achilles: %s: %s\n", id, msg)
		}
	}

	repo := vcs.RepoState(absTarget)
	switch {
	case tools[0] == optInSecretsHistory:
		o.secretsHistory = false
		report("run", "--secrets-history was asked for, but the tool registry has no scanner marked `optIn: secrets-history`; the git history was not scanned")
	case !repo.InWorkTree:
		o.secretsHistory = false
		report("run", fmt.Sprintf("--secrets-history: the target is not a git repository that git will read (%s); its history was not scanned", repo.Reason))
	case o.diffRef != "" && !vcs.HasCommit(absTarget, o.diffRef):
		o.secretsHistory = false
		report("run", fmt.Sprintf("--secrets-history: --diff %s does not name a commit in this checkout; the commits under review were not scanned", o.diffRef))
	default:
		if repo.Shallow {
			report("partial", "the checkout is shallow, so only the commits that were fetched were scanned for credentials; fetch the full history (actions/checkout `fetch-depth: 0`, GitLab `GIT_DEPTH: 0`)")
		}
		if repo.Prefix != "" {
			report("partial", fmt.Sprintf("the target is the directory %s inside its repository; the history scan covers the whole repository and names files relative to its root, so scan the root instead", repo.Prefix))
		}
	}
	return diags
}

// collapseHistory removes history findings that add nothing to the report:
//
//   - one whose credential is also reported in the files as they are now. It is
//     the same leak, and the working-tree finding is the one with a line to fix;
//   - repeats of one credential across commits (a line that was moved or re-added
//     is "added" again each time). The earliest commit is kept, and its message
//     says how many more there are.
//
// A credential is recognized by tool and fingerprint: the fingerprint is made from
// the matched text, not from where it was found.
func collapseHistory(scan *model.Scan, warn io.Writer) {
	key := func(f model.Finding) string { return f.Tool + "\x00" + f.RuleID + "\x00" + f.Fingerprint }
	inTree := map[string]bool{}
	history := 0
	for _, f := range scan.Findings {
		if f.Commit == "" {
			inTree[key(f)] = true
		} else {
			history++
		}
	}
	if history == 0 {
		return
	}

	kept := scan.Findings[:0:0]
	first := map[string]int{} // credential -> index in kept of the commit kept for it
	extra := map[string]int{}
	alsoInTree := 0
	for _, f := range scan.Findings {
		if f.Commit == "" {
			kept = append(kept, f)
			continue
		}
		k := key(f)
		if inTree[k] {
			alsoInTree++
			continue
		}
		if i, seen := first[k]; seen {
			extra[k]++
			// Keep the earliest commit: that is when the credential leaked.
			if f.CommitDate != "" && (kept[i].CommitDate == "" || f.CommitDate < kept[i].CommitDate) {
				kept[i] = f
			}
			continue
		}
		first[k] = len(kept)
		kept = append(kept, f)
	}
	repeats := 0
	for k, n := range extra {
		repeats += n
		kept[first[k]].Message += fmt.Sprintf(" It was committed %d more time(s) after that.", n)
	}
	scan.Findings = kept
	fmt.Fprintf(warn, "achilles: git history: %d credential(s) found only in the history", len(first))
	if alsoInTree > 0 {
		fmt.Fprintf(warn, "; %d more are still in the files and are reported there", alsoInTree)
	}
	if repeats > 0 {
		fmt.Fprintf(warn, "; %d repeat(s) of the same credential in other commits folded in", repeats)
	}
	fmt.Fprintln(warn)
}

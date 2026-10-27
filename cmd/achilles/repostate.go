package main

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vcs"
)

// Besides the scanners' configuration and .achilles.yaml, three things Achilles
// itself reads can sit inside the scanned repository and decide what a scan
// reports:
//
//   - the baseline: every fingerprint in it is a finding that is not reported;
//   - the Evidence Vault, when it is committed: its feedback history is what
//     --calibrate dismisses findings on and what --rag shows the model as examples;
//   - the generated-rule repository: deleting a rule deletes its findings.
//
// A pull request can change any of them along with the code. The policy is the
// one used for scanner configuration: with --diff, a change to one of them in the
// commits under review is called out on stderr and at the top of every report; a
// committed vault whose feedback is in use is named; and --no-repo-config refuses
// that feedback. (Cached verdicts need no such care: they are signed with a key
// that is not in the repository.)

// insideTarget returns path relative to the scan target, slash-separated, and
// whether it lies inside it.
func insideTarget(absTarget, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(absTarget, abs)
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// applyRepoStatePolicy must run before the AI review: it can turn --calibrate and
// --rag off.
func applyRepoStatePolicy(o *options, absTarget string, scan *model.Scan, warn io.Writer) {
	// Feedback from a vault that is committed with the code.
	vaultRel, feedbackInUse := "", false
	if o.vaultBackend == "" || o.vaultBackend == "file" {
		if rel, ok := insideTarget(absTarget, o.vaultPath); ok && (o.calibrate || o.ragOn) && vcs.Tracked(absTarget, rel) {
			var uses []string
			if o.calibrate {
				uses = append(uses, "--calibrate")
			}
			if o.ragOn {
				uses = append(uses, "--rag")
			}
			if o.noRepoConfig {
				fmt.Fprintf(warn, "achilles: --no-repo-config: the Evidence Vault (%s) is committed in the scanned repository, so its feedback history could have been written by the change under review; %s off for this run\n",
					rel, strings.Join(uses, " and "))
				o.calibrate, o.ragOn = false, false
			} else {
				vaultRel, feedbackInUse = rel, true
				scan.RepoConfig = append(scan.RepoConfig, "feedback: "+rel)
				fmt.Fprintf(warn, "achilles: %s uses the feedback history in %s, which is committed in the scanned repository: whoever can change the repository can change that history (--no-repo-config to refuse it, or keep the vault elsewhere with --vault)\n",
					strings.Join(uses, " and "), rel)
			}
		}
	}

	if o.diffRef == "" {
		return
	}
	type state struct{ kind, path string }
	var states []state
	for _, p := range []string{o.baselinePath, o.prMini} {
		if rel, ok := insideTarget(absTarget, p); ok {
			states = append(states, state{"baseline", rel})
		}
	}
	if feedbackInUse {
		states = append(states, state{"feedback", vaultRel})
	}
	// The threat context, when it changed which scanners ran.
	if p := o.toolPlan; p != nil && p.ContextFile != "" && slices.Contains(scan.RepoConfig, "threat context: "+p.ContextFile) {
		states = append(states, state{"threat context", p.ContextFile})
	}
	// No check that the directory exists: one the change deleted is the case that matters most.
	if rel, ok := insideTarget(absTarget, o.ruleRepoDir); ok {
		states = append(states, state{"generated rules", rel})
	}
	var changed []string
	for _, s := range states {
		if len(vcs.CommittedChanges(absTarget, o.diffRef, s.path)) > 0 {
			changed = append(changed, s.kind+": "+s.path)
		}
	}
	if len(changed) > 0 {
		scan.RepoConfigChanged = append(scan.RepoConfigChanged, changed...)
		fmt.Fprintf(warn, "achilles: WARNING: this change modifies what the scan is compared against (%s). It can hide findings in the same change; review it as part of this scan.\n",
			strings.Join(changed, "; "))
	}
}

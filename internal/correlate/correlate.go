// Package correlate groups findings from DIFFERENT tools that describe the same
// defect, so the triage layer spends one pair of LLM calls per defect instead of
// one pair per tool that happened to report it (DESIGN.md §14, "triage clusters
// not raw findings").
//
// Achilles runs overlapping engines on purpose — Opengrep+gosec on Go,
// Trivy+Checkov on IaC, Gitleaks+TruffleHog on secrets — so the same defect
// routinely arrives two or three times. Correlation is deliberately conservative
// because the cost of a WRONG merge (a verdict copied between two genuinely
// different defects) is much higher than the cost of a missed merge (one extra
// LLM call):
//
//   - the key is exact file + start line + the CWE set, all of which must match;
//   - a finding with no CWE, or no line number, is never clustered (too little
//     evidence to prove two reports are the same defect);
//   - members must come from DIFFERENT tools — one tool reporting twice at one
//     line is reporting two instances, not the cross-tool overlap we target;
//   - shadow findings (§9.4 rule flywheel) never cluster, so the shadow window's
//     report-only semantics stay untouched.
//
// Correlation does NOT collapse the reported or gated set. Every finding keeps
// its own ID, fingerprint, severity, and behaviour under --baseline,
// --file-issues, and --fail-on. That is what makes this safe to enable by
// default: nothing downstream of triage can change identity.
package correlate

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// Cluster is a set of findings that describe one defect. Rep is the index of the
// representative (the highest-severity member — the one worth spending LLM calls
// on); Members holds the indices of the others. Indices refer to the findings
// slice passed to Clusters, so callers can mutate the originals in place.
type Cluster struct {
	Rep     int
	Members []int
}

// Clusters groups findings that describe the same defect. Only genuine clusters
// (2+ findings) are returned; a finding reported by exactly one tool needs no
// entry. Output is deterministic for a given input order: clusters are returned
// in order of their representative's index, and ties on severity resolve to the
// earlier index.
func Clusters(findings []model.Finding) []Cluster {
	byKey := map[string][]int{}
	var order []string
	for i, f := range findings {
		k, ok := key(f)
		if !ok {
			continue
		}
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], i)
	}

	var out []Cluster
	for _, k := range order {
		idx := byKey[k]
		if len(idx) < 2 {
			continue
		}
		// Same-tool reports are separate instances, not cross-tool overlap. Keep
		// the first index per tool and leave any repeats to be triaged normally.
		seenTool := map[string]bool{}
		distinct := make([]int, 0, len(idx))
		for _, i := range idx {
			if seenTool[findings[i].Tool] {
				continue
			}
			seenTool[findings[i].Tool] = true
			distinct = append(distinct, i)
		}
		if len(distinct) < 2 {
			continue
		}

		rep := distinct[0]
		for _, i := range distinct[1:] {
			if findings[i].Severity.Rank() > findings[rep].Severity.Rank() {
				rep = i
			}
		}
		members := make([]int, 0, len(distinct)-1)
		for _, i := range distinct {
			if i != rep {
				members = append(members, i)
			}
		}
		out = append(out, Cluster{Rep: rep, Members: members})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Rep < out[j].Rep })
	return out
}

// Annotate records cluster membership on each clustered finding, so a report can
// show that three tools agree on one defect without dropping any of them. It
// only writes Finding.Correlated, which is descriptive and is not part of a
// finding's ID or fingerprint.
func Annotate(findings []model.Finding, clusters []Cluster) {
	for _, c := range clusters {
		all := append([]int{c.Rep}, c.Members...)
		for _, i := range all {
			var others []string
			for _, j := range all {
				if j != i {
					others = append(others, findings[j].Tool+":"+findings[j].RuleID)
				}
			}
			sort.Strings(others)
			findings[i].Correlated = others
		}
	}
}

// Saved reports how many LLM triage passes the clusters avoid: every member
// beyond its cluster's representative inherits a verdict instead of being
// triaged.
func Saved(clusters []Cluster) int {
	n := 0
	for _, c := range clusters {
		n += len(c.Members)
	}
	return n
}

// key returns the cluster key for a finding, and whether it is eligible to
// cluster at all. See the package comment for why each guard exists.
func key(f model.Finding) (string, bool) {
	if f.Shadow || len(f.CWE) == 0 || f.Location.Region.StartLine <= 0 {
		return "", false
	}
	cwes := make([]string, 0, len(f.CWE))
	for _, c := range f.CWE {
		if c = strings.TrimSpace(c); c != "" {
			cwes = append(cwes, strings.ToUpper(c))
		}
	}
	if len(cwes) == 0 {
		return "", false
	}
	sort.Strings(cwes)
	return strings.Join([]string{
		f.Location.File,
		strconv.Itoa(f.Location.Region.StartLine),
		strings.Join(cwes, ","),
	}, "|"), true
}

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
//   - two findings must be at the same file and line, and be about the same kind
//     of weakness: they share a CWE, or CWEs that are parent and child (one tool
//     says CWE-78, another CWE-77). Requiring the identical SET of CWEs, as this
//     used to, meant overlapping tools almost never clustered;
//   - two credential findings on one line are the same credential, and two
//     dependency advisories with the same id against the same manifest are the
//     same advisory. Neither is ever sent to a model, so these clusters save no
//     calls; they let a report say that two tools agree;
//   - any other finding with no CWE, or no line number, is never clustered (too
//     little evidence to prove two reports are the same defect). That still
//     excludes most infrastructure-as-code findings, whose rule ids differ per
//     tool and carry no CWE;
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
	// Findings are first grouped by place (the same file and line; for a
	// dependency advisory, the same manifest). Within a place, two findings are
	// the same defect when they share a label: a CWE family, an advisory id, or
	// "a credential". Sharing is transitive within the place.
	type member struct {
		idx    int
		labels []string
	}
	byPlace := map[string][]member{}
	var places []string
	for i, f := range findings {
		place, labels, ok := describe(f)
		if !ok {
			continue
		}
		if _, seen := byPlace[place]; !seen {
			places = append(places, place)
		}
		byPlace[place] = append(byPlace[place], member{i, labels})
	}

	var out []Cluster
	for _, place := range places {
		ms := byPlace[place]
		if len(ms) < 2 {
			continue
		}
		// Union-find over the members of this place, joined through shared labels.
		parent := make([]int, len(ms))
		for i := range parent {
			parent[i] = i
		}
		find := func(i int) int {
			for parent[i] != i {
				parent[i] = parent[parent[i]]
				i = parent[i]
			}
			return i
		}
		firstWith := map[string]int{}
		for i, m := range ms {
			for _, l := range m.labels {
				if j, ok := firstWith[l]; ok {
					if a, b := find(i), find(j); a != b {
						if a < b {
							a, b = b, a
						}
						parent[a] = b // the earlier member stays the root: stable order
					}
				} else {
					firstWith[l] = i
				}
			}
		}
		groups := map[int][]int{}
		var roots []int
		for i, m := range ms {
			r := find(i)
			if _, seen := groups[r]; !seen {
				roots = append(roots, r)
			}
			groups[r] = append(groups[r], m.idx)
		}

		for _, r := range roots {
			idx := groups[r]
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
// triaged. Dependency advisories and credential findings are never sent to a
// model, so a cluster of those saves nothing and is not counted.
func Saved(findings []model.Finding, clusters []Cluster) int {
	n := 0
	for _, c := range clusters {
		for _, i := range c.Members {
			if i < len(findings) && !findings[i].IsSecret() && !findings[i].IsDependencyAdvisory() {
				n++
			}
		}
	}
	return n
}

// Size is the number of findings that belong to some cluster.
func Size(clusters []Cluster) int {
	n := 0
	for _, c := range clusters {
		n += 1 + len(c.Members)
	}
	return n
}

// describe returns where a finding is and what it is about, and whether it is
// eligible to cluster at all. See the package comment for why each guard exists.
func describe(f model.Finding) (place string, labels []string, ok bool) {
	if f.Shadow || f.Location.File == "" {
		return "", nil, false
	}
	switch {
	case f.IsDependencyAdvisory():
		// Two SCA tools reporting one advisory against one manifest. Advisories
		// often carry no useful line, so the manifest is the place.
		id := strings.ToUpper(strings.TrimSpace(f.RuleID))
		if id == "" {
			return "", nil, false
		}
		return "advisory|" + f.Location.File, []string{id}, true
	case f.Location.Region.StartLine <= 0:
		return "", nil, false
	case f.IsSecret():
		// Two secret scanners on one line found the same credential, whatever
		// each calls its rule.
		labels = []string{"credential"}
	default:
		seen := map[string]bool{}
		for _, c := range f.CWE {
			if fam := family(c); fam != "" && !seen[fam] {
				seen[fam] = true
				labels = append(labels, fam)
			}
		}
		if len(labels) == 0 {
			return "", nil, false
		}
		sort.Strings(labels)
	}
	return f.Location.File + "|" + strconv.Itoa(f.Location.Region.StartLine), labels, true
}

// cweFamilies maps a CWE to the broader weakness it is a kind of, for the small
// set of parent and child ids that scanners use interchangeably for one defect:
// one tool reports command injection as CWE-78 and another as CWE-77. Requiring
// the same id, let alone the same set of ids, meant overlapping tools almost
// never clustered. Ids not listed are their own family.
//
// Only relations where the child is a specific form of the parent are listed.
// Different weaknesses that often sit on one line (injection and missing
// authentication, say) stay apart.
var cweFamilies = map[string]string{
	"CWE-78": "CWE-77", "CWE-88": "CWE-77", // OS command and argument injection: command injection
	"CWE-564": "CWE-89",                     // Hibernate injection: SQL injection
	"CWE-80":  "CWE-79",                     // basic XSS: XSS
	"CWE-23":  "CWE-22", "CWE-36": "CWE-22", // relative and absolute traversal: path traversal
	"CWE-95":  "CWE-94",                        // eval injection: code injection
	"CWE-259": "CWE-798", "CWE-321": "CWE-798", // hard-coded password or key: hard-coded credentials
	"CWE-328": "CWE-327", "CWE-916": "CWE-327", "CWE-326": "CWE-327", // weak hash, weak password hash, weak strength: weak cryptography
	"CWE-338": "CWE-330",                       // weak PRNG: insufficient randomness
	"CWE-296": "CWE-295", "CWE-297": "CWE-295", // chain and host validation: certificate validation
}

// family returns the label a CWE clusters under.
func family(cwe string) string {
	c := strings.ToUpper(strings.TrimSpace(cwe))
	if c == "" {
		return ""
	}
	if parent, ok := cweFamilies[c]; ok {
		return parent
	}
	return c
}

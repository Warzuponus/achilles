package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/config"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/surface"
	"github.com/Warzuponus/achilles/internal/toolchain"
)

const profileFull = "full"

// toolNeed is what a scanner must find in the target before it has anything to
// analyze, and what to say when it is missing or present.
type toolNeed struct {
	marker  string
	missing string // why the scanner is skipped without it
	found   string // why an opt-in scanner is worth adding with it
}

// toolNeeds lists the scanners that analyze nothing without a particular kind of
// project file. A scanner that is not listed is never skipped for a missing file.
// Markers in tests and out-of-scope paths do not count.
var toolNeeds = map[string]toolNeed{
	"gosec": {marker: surface.MarkerGoMod,
		missing: "no go.mod outside tests and out-of-scope paths; gosec type-checks Go modules and has nothing to analyze without one"},
	"govulncheck": {marker: surface.MarkerGoMod,
		missing: "no go.mod outside tests and out-of-scope paths; govulncheck reads a Go module's dependencies"},
	"psalm": {marker: surface.MarkerPsalm,
		missing: "no psalm.xml at the repository root; Achilles runs Psalm with the project's own psalm.xml"},
	"findsecbugs": {marker: surface.MarkerBytecode,
		missing: "no compiled .class, .jar or .war in build output (build/, target/, out/ ...); FindSecBugs analyzes bytecode, so build the project first"},
	"security-code-scan": {marker: surface.MarkerDotNet,
		missing: "no .csproj, .vbproj or .sln; Security Code Scan builds a .NET project"},
	"railroader": {marker: surface.MarkerRails,
		missing: "not a Rails application (no config/routes.rb or config/application.rb)"},
	"checkov": {marker: surface.MarkerIaC,
		missing: "no infrastructure-as-code files (Terraform, Kubernetes, Helm, CloudFormation, ARM, Dockerfiles, Compose)"},
	"zizmor": {marker: surface.MarkerWorkflows,
		missing: "no GitHub Actions workflows",
		found:   "the repository has GitHub Actions workflows, which zizmor audits"},
}

// prepareModel is the Model phase, run before the scanners are chosen: it reads
// the repository's threat-context file, maps the attack surface, picks the scan
// depth and decides which scanners are worth running. Recording the plan in the
// vault and writing --plan-out happen later, in recordPlan, once the vault is open.
//
// The plan only ever skips a scanner that has nothing to analyze, with the reason,
// and only adds an opt-in scanner when the repository's context file is present
// (or --all-tools) and the scanner is installed. It never removes a finding.
func prepareModel(o *options, cfg *config.Config, absTarget string, w io.Writer) error {
	if err := loadThreatContext(o, absTarget, w); err != nil {
		return err
	}
	if !o.planWanted() && o.threatContext == nil && o.profile != profileFull && !o.allTools {
		return nil
	}
	if fi, err := os.Stat(absTarget); err == nil && !fi.IsDir() {
		if o.planOut != "" {
			return fmt.Errorf("--plan-out: the target is a file; the surface map needs a directory")
		}
		return nil
	}
	m, err := surface.Build(absTarget, surface.Options{Context: o.threatContext})
	if err != nil {
		if o.planOut != "" {
			return fmt.Errorf("--plan-out: map the attack surface: %w", err)
		}
		fmt.Fprintf(w, "achilles: surface map failed (%v); every scanner in the profile runs and the AI review keeps severity order\n", err)
		return nil
	}
	o.surface = m
	fmt.Fprintln(w, planSummary(m))
	if m.Truncated {
		fmt.Fprintf(w, "achilles: surface map is INCOMPLETE: the walk stopped after %d file(s) / %d MiB; files past that score 0 and are reviewed in severity order, and the scan plan skips no scanner\n",
			m.FilesRead, m.BytesRead>>20)
	}
	fmt.Fprintf(w, "achilles: scan depth: %s (%s)\n", m.Depth.Level, strings.Join(m.Depth.Reasons, "; "))
	o.toolPlan = decideTools(o, cfg, m, canLaunch(o.runnerKind))
	m.ToolPlan = o.toolPlan
	for _, d := range o.toolPlan.Decisions {
		line := fmt.Sprintf("achilles: scan plan %s %s: %s", map[string]string{
			model.ToolSkipped: "skips", model.ToolAdded: "adds", model.ToolRecommended: "recommends",
		}[d.Action], d.Tool, d.Reason)
		if d.Fix != "" && d.Action == model.ToolSkipped {
			line += " (" + d.Fix + " runs it anyway)"
		}
		fmt.Fprintln(w, line)
	}
	if o.allTools {
		fmt.Fprintln(w, "achilles: --all-tools: the scan plan skips no scanner")
	}
	return nil
}

// loadThreatContext reads .achilles/threat-context.yaml. It is the repository's
// own say-so, so --no-repo-config ignores it. A file that does not parse fails the
// run: a misspelled answer that silently counted as unknown would change the scan.
func loadThreatContext(o *options, absTarget string, w io.Writer) error {
	if o.noRepoConfig {
		for _, name := range surface.ContextFiles {
			if _, err := os.Stat(filepath.Join(absTarget, filepath.FromSlash(name))); err == nil {
				fmt.Fprintf(w, "achilles: --no-repo-config: ignoring the threat context in %s\n", name)
			}
		}
		return nil
	}
	if fi, err := os.Stat(absTarget); err != nil || !fi.IsDir() {
		return nil // a file target has no context file; a missing one fails later, with its own error
	}
	c, err := surface.LoadContext(absTarget)
	if err != nil {
		return fmt.Errorf("threat context: %w (fix it or delete it; --no-repo-config ignores it)", err)
	}
	if c == nil {
		return nil
	}
	o.threatContext = c
	answered := 0
	for _, v := range []*bool{c.BusinessCritical, c.ConfidentialData, c.ExternallyFacing, c.Autonomous, c.MultiAgent} {
		if v != nil {
			answered++
		}
	}
	fmt.Fprintf(w, "achilles: threat context from %s: %d of 5 depth questions answered, %d crown-jewel and %d out-of-scope path pattern(s)\n",
		c.File, answered, len(c.CrownJewels), len(c.OutOfScope))
	return nil
}

// canLaunch reports whether a scanner can be started by the chosen runner, and
// if not, what to do about it.
func canLaunch(runnerKind string) func(config.ToolConfig) (bool, string) {
	return func(tc config.ToolConfig) (bool, string) {
		if runnerKind == "docker" && tc.Image != "" {
			return true, ""
		}
		if tc.Bin != "" {
			if _, _, err := toolchain.LookBin(tc.Bin); err == nil {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%s is not installed (`achilles tools install %s`)", tc.ID, tc.ID)
	}
}

// decideTools is the scan plan's choice of scanners. It is deterministic and
// reads only the map, the registry and the flags.
//
// Skips apply only to scanners the profile turns on, never to one asked for by
// name (--with, --secrets-history), never under --all-tools and never from a map
// that stopped early. Additions apply only to opt-in scanners, only when the
// repository's threat-context file is present or --all-tools was given, and only
// when the scanner can be launched; otherwise the plan recommends instead.
func decideTools(o *options, cfg *config.Config, m *surface.Map, launch func(config.ToolConfig) (bool, string)) *model.ToolPlan {
	plan := &model.ToolPlan{Depth: m.Depth.Level, DepthReasons: m.Depth.Reasons, AllTools: o.allTools}
	if m.Context != nil {
		plan.ContextFile = m.Context.File
	}
	for _, tc := range cfg.Tools {
		if tc.ID == "syft" {
			continue // SBOM generator, not a findings scanner
		}
		asked := o.optedIn(tc.OptIn)
		need, hasNeed := toolNeeds[tc.ID]
		switch {
		case tc.RunsInProfile(o.profile) && !asked:
			if o.allTools || m.Truncated {
				continue
			}
			if hasNeed && !m.HasMarker(need.marker) && languagesPresent(tc, m) {
				plan.Decisions = append(plan.Decisions, model.ToolDecision{Tool: tc.ID, Action: model.ToolSkipped, Reason: need.missing, Fix: "--all-tools"})
			} else if why := onlyOutOfScope(tc, m); why != "" {
				plan.Decisions = append(plan.Decisions, model.ToolDecision{Tool: tc.ID, Action: model.ToolSkipped, Reason: why, Fix: "--all-tools"})
			}
		case tc.OptIn != "" && !asked && hasNeed && need.found != "" && m.HasMarker(need.marker):
			fix := "--with " + tc.OptIn
			switch ok, why := launch(tc); {
			case !o.allTools && m.Context == nil:
				plan.Decisions = append(plan.Decisions, model.ToolDecision{Tool: tc.ID, Action: model.ToolRecommended,
					Reason: need.found + "; run it with " + fix + ", or let a threat-context file add it", Fix: fix})
			case ok:
				by := "--all-tools"
				if !o.allTools {
					by = "the threat-context file is present"
				}
				plan.Decisions = append(plan.Decisions, model.ToolDecision{Tool: tc.ID, Action: model.ToolAdded, Reason: need.found + " (" + by + ")"})
			default:
				plan.Decisions = append(plan.Decisions, model.ToolDecision{Tool: tc.ID, Action: model.ToolRecommended,
					Reason: need.found + ", but " + why, Fix: fix})
			}
		}
	}
	if m.Depth.Level == surface.DepthFull && o.profile != profileFull {
		plan.Decisions = append(plan.Decisions, model.ToolDecision{Tool: "--profile full", Action: model.ToolRecommended,
			Reason: "scan depth is full (" + strings.Join(m.Depth.Reasons, "; ") + "); the full profile adds the per-language analyzers", Fix: "--profile full"})
	}
	return plan
}

// languagesPresent reports whether the target has code in one of the tool's
// languages (anywhere, tests included). A language-agnostic tool always has.
func languagesPresent(tc config.ToolConfig, m *surface.Map) bool {
	if len(tc.Languages) == 0 || slices.Contains(tc.Languages, "generic") {
		return true
	}
	for _, l := range tc.Languages {
		if m.Languages[strings.ToLower(l)].Files > 0 {
			return true
		}
	}
	return false
}

// onlyOutOfScope explains why a language-specific tool has nothing useful to
// analyze: every file in its languages is a test or matches an out-of-scope
// pattern. A tool whose languages are absent altogether is left to the
// applicability check, which already skips it.
func onlyOutOfScope(tc config.ToolConfig, m *surface.Map) string {
	if len(tc.Languages) == 0 || slices.Contains(tc.Languages, "generic") {
		return ""
	}
	var found []string
	for _, l := range tc.Languages {
		c := m.Languages[strings.ToLower(l)]
		if c.InScope > 0 {
			return ""
		}
		if c.Files > 0 {
			found = append(found, fmt.Sprintf("%s: %d file(s)", l, c.Files))
		}
	}
	if len(found) == 0 {
		return ""
	}
	sort.Strings(found)
	where := "tests"
	if m.Context != nil && len(m.Context.OutOfScope) > 0 {
		where = "tests and paths the threat context marks out of scope"
	}
	return fmt.Sprintf("its languages (%s) appear only in %s", strings.Join(found, ", "), where)
}

// planSkips reports whether the scan plan skips this tool.
func (o *options) planSkips(id string) bool {
	return slices.Contains(o.toolPlan.Skipped(), id)
}

// planAdds reports whether the scan plan adds this opt-in tool.
func (o *options) planAdds(id string) bool {
	return slices.Contains(o.toolPlan.Added(), id)
}

// applyToolPlan puts the plan in the scan, so every report shows it, and lists
// the threat-context file with the repository configuration in effect when it
// changed which scanners ran: a scanner it skipped finds nothing.
func applyToolPlan(o *options, scan *model.Scan) {
	p := o.toolPlan
	if p == nil {
		return
	}
	scan.ToolPlan = p
	if p.ContextFile != "" && len(p.Skipped()) > 0 {
		scan.RepoConfig = append(scan.RepoConfig, "threat context: "+p.ContextFile)
	}
}

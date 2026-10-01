package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// sarifLevel maps our severity onto SARIF result levels.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIFReport emits one unified SARIF 2.1.0 document across all tools —
// the format GitHub code scanning and other consumers ingest.
func WriteSARIFReport(w io.Writer, s model.Scan) error {
	// Results must be a non-nil array: SARIF requires `results` to be an array,
	// and GitHub code scanning rejects `"results": null` (which a nil slice emits).
	run := model.SarifRun{
		Tool:    model.SarifTool{Driver: model.SarifDriver{Name: "achilles"}},
		Results: []model.SarifResult{},
	}
	for _, f := range s.Findings {
		run.Results = append(run.Results, model.SarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: model.SarifMessage{Text: f.Message},
			Locations: []model.SarifLocation{{
				PhysicalLocation: model.SarifPhysicalLocation{
					ArtifactLocation: model.SarifArtifactLocation{URI: f.Location.File},
					Region:           model.SarifRegion{StartLine: f.Location.Region.StartLine},
				},
			}},
			Fingerprints: map[string]string{"achilles/v1": f.Fingerprint},
		})
	}
	log := model.SarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []model.SarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// --- JUnit ---

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// WriteJUnit emits JUnit XML (each finding is a failing test case) for CI
// systems that render test reports.
func WriteJUnit(w io.Writer, s model.Scan) error {
	suite := junitSuite{Name: "achilles", Tests: len(s.Findings), Failures: len(s.Findings)}
	for _, f := range s.Findings {
		loc := f.Location.File
		if f.Location.Region.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Region.StartLine)
		}
		suite.Cases = append(suite.Cases, junitCase{
			Name:      fmt.Sprintf("%s (%s)", f.RuleID, loc),
			Classname: f.Tool,
			Failure:   &junitFailure{Message: f.Message, Text: fmt.Sprintf("[%s] %s at %s", f.Severity, f.RuleID, loc)},
		})
	}
	doc := junitSuites{Tests: len(s.Findings), Failures: len(s.Findings), Suites: []junitSuite{suite}}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(doc)
}

// --- Markdown (PR comment) ---

// WriteMarkdown emits a Markdown summary suitable for a PR comment.
func WriteMarkdown(w io.Writer, s model.Scan) error {
	fmt.Fprintf(w, "## Achilles scan — %d finding(s)\n\n", len(s.Findings))
	if len(s.Findings) == 0 {
		_, err := io.WriteString(w, "No findings. ✅\n")
		return err
	}
	fmt.Fprintln(w, "| Severity | Rule | Location | Verdict | Message |")
	fmt.Fprintln(w, "|----------|------|----------|---------|---------|")
	for _, f := range s.Findings {
		loc := f.Location.File
		if f.Location.Region.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Region.StartLine)
		}
		verdict := "—"
		if f.Verdict != nil {
			verdict = string(f.Verdict.Classification)
			switch {
			case f.Verdict.Refuted:
				verdict += " (refuted)"
			case f.Verdict.Overturned:
				verdict += " (**overturned by judge**)"
			}
		}
		fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s |\n",
			f.Severity, f.RuleID, loc, verdict, mdEscape(f.Message))
	}
	return nil
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

// --- GitHub Actions annotations ---

// WriteGitHubAnnotations emits GitHub Actions workflow commands so findings show
// up as inline annotations on the PR diff (no API calls required).
func WriteGitHubAnnotations(w io.Writer, s model.Scan) error {
	for _, f := range s.Findings {
		level := "warning"
		if f.Severity.Rank() >= model.SeverityHigh.Rank() {
			level = "error"
		}
		_, err := fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			level, ghProp(f.Location.File), f.Location.Region.StartLine,
			ghProp(f.RuleID), ghData(f.Message))
		if err != nil {
			return err
		}
	}
	return nil
}

func ghData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

func ghProp(s string) string {
	s = ghData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	return strings.ReplaceAll(s, ",", "%2C")
}

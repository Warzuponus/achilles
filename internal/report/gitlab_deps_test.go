package report

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// The advisories as osv-scanner and Trivy report them, a code finding that
// belongs in the SAST report, and an advisory whose message names no package.
func gitlabDepScan() model.Scan {
	return model.Scan{
		Target: "/repo",
		Tools:  []string{"osv-scanner", "trivy", "gosec"},
		Findings: []model.Finding{
			{
				ID: "d1", Tool: "osv-scanner", RuleID: "CVE-2020-14343", Severity: model.SeverityCritical,
				Message:  "Package 'pyyaml@5.3.1' is vulnerable to 'CVE-2020-14343' (also known as 'PYSEC-2021-142', 'GHSA-8q59-q68h-6hv4').",
				Location: model.Location{File: "requirements.txt"}, Fingerprint: "fd1",
			},
			{
				ID: "d2", Tool: "osv-scanner", RuleID: "GHSA-p6mc-m468-83gw", Severity: model.SeverityHigh,
				Message:  "Package '@babel/traverse@7.22.5' is vulnerable to 'GHSA-p6mc-m468-83gw'.",
				Location: model.Location{File: "web/package-lock.json"}, Fingerprint: "fd2",
			},
			{
				ID: "d3", Tool: "Trivy", Scanner: "trivy", RuleID: "CVE-2022-28948", Severity: model.SeverityHigh,
				Message:  "Package: gopkg.in/yaml.v3\nInstalled Version: v3.0.0\nVulnerability CVE-2022-28948\nSeverity: HIGH\nFixed Version: 3.0.0-20220521103104-8f96da9f5d5e\nLink: [CVE-2022-28948](https://avd.aquasec.com/nvd/cve-2022-28948)",
				Location: model.Location{File: "go.mod", Region: model.Region{StartLine: 9}}, Fingerprint: "fd3",
			},
			{
				ID: "d4", Tool: "govulncheck", RuleID: "GO-2024-2611", Severity: model.SeverityMedium,
				Message: "Infinite loop in JSON unmarshaling", Location: model.Location{File: "go.mod"}, Fingerprint: "fd4",
			},
			{
				ID: "c1", Tool: "gosec", RuleID: "G204", Severity: model.SeverityHigh, Message: "Subprocess launched with variable",
				Location: model.Location{File: "cmd/run.go", Region: model.Region{StartLine: 41}}, Fingerprint: "fc1",
			},
		},
	}
}

func TestWriteGitLabDependencyScanning(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitLabDependencyScanning(&buf, gitlabDepScan(), gitlabMeta); err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("ACHILLES_GITLAB_SAMPLE_DIR"); out != "" {
		_ = os.WriteFile(out+"/gl-dependency-scanning-report.json", buf.Bytes(), 0o600) // for schema validation by hand
	}
	var doc struct {
		Scan struct {
			Type string `json:"type"`
		} `json:"scan"`
		Vulnerabilities []struct {
			Name     string `json:"name"`
			Solution string `json:"solution"`
			Location struct {
				File       string `json:"file"`
				Dependency struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
					Version string `json:"version"`
				} `json:"dependency"`
			} `json:"location"`
		} `json:"vulnerabilities"`
		DependencyFiles []struct {
			Path           string `json:"path"`
			PackageManager string `json:"package_manager"`
			Dependencies   []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"dependencies"`
		} `json:"dependency_files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Scan.Type != "dependency_scanning" {
		t.Errorf("scan.type = %q", doc.Scan.Type)
	}
	if len(doc.Vulnerabilities) != 4 {
		t.Fatalf("%d vulnerabilities, want the 4 advisories (not the gosec finding)", len(doc.Vulnerabilities))
	}
	want := []struct{ file, pkg, version string }{
		{"requirements.txt", "pyyaml", "5.3.1"},
		{"web/package-lock.json", "@babel/traverse", "7.22.5"}, // a scoped name keeps its @
		{"go.mod", "gopkg.in/yaml.v3", "v3.0.0"},
		{"go.mod", "unknown", "unknown"}, // named nowhere in the message, still reported
	}
	for i, w := range want {
		l := doc.Vulnerabilities[i].Location
		if l.File != w.file || l.Dependency.Package.Name != w.pkg || l.Dependency.Version != w.version {
			t.Errorf("vulnerability %d at %s %s@%s, want %s %s@%s", i, l.File, l.Dependency.Package.Name, l.Dependency.Version, w.file, w.pkg, w.version)
		}
	}
	if s := doc.Vulnerabilities[2].Solution; s != "Upgrade gopkg.in/yaml.v3 to 3.0.0-20220521103104-8f96da9f5d5e or later." {
		t.Errorf("Trivy's fixed version not turned into a solution: %q", s)
	}
	managers := map[string]string{}
	for _, f := range doc.DependencyFiles {
		managers[f.Path] = f.PackageManager
	}
	if managers["requirements.txt"] != "pip" || managers["web/package-lock.json"] != "npm" || managers["go.mod"] != "go" || len(managers) != 3 {
		t.Errorf("dependency_files = %v", managers)
	}
}

// The SAST report still leaves advisories out, and the dependency report has
// valid empty arrays when there are none.
func TestWriteGitLabDependencyScanning_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitLabDependencyScanning(&buf, model.Scan{Target: "/repo"}, gitlabMeta); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	if v, ok := doc["vulnerabilities"].([]any); !ok || len(v) != 0 {
		t.Errorf("vulnerabilities = %v, want []", doc["vulnerabilities"])
	}
	if v, ok := doc["dependency_files"].([]any); !ok || len(v) != 0 {
		t.Errorf("dependency_files = %v, want []", doc["dependency_files"])
	}
}

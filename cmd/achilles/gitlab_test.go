package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// End to end: one run writes the three GitLab reports from the same scan.
func TestRun_WritesGitLabReports(t *testing.T) {
	cfg, target, vaultPath := fakeScanFixture(t)
	t.Setenv("CI_COMMIT_SHA", "") // a developer's shell or another CI system must not leak into the reports
	out := t.TempDir()
	sast := filepath.Join(out, "gl-sast-report.json")
	secrets := filepath.Join(out, "gl-secret-detection-report.json")
	quality := filepath.Join(out, "gl-code-quality-report.json")

	before := time.Now().UTC().Add(-time.Second)
	if err := run([]string{"--config", cfg, "--vault", vaultPath,
		"--gitlab-sast", sast, "--gitlab-secret-detection", secrets, "--gitlab-code-quality", quality, target}); err != nil {
		t.Fatalf("run: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	read := func(path string, into any) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("report not written: %v", err)
		}
		if err := json.Unmarshal(b, into); err != nil {
			t.Fatalf("%s is not JSON: %v\n%s", filepath.Base(path), err, b)
		}
	}
	type securityReport struct {
		Version string `json:"version"`
		Scan    struct {
			Type      string `json:"type"`
			Status    string `json:"status"`
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
			Scanner   struct {
				Version string `json:"version"`
			} `json:"scanner"`
		} `json:"scan"`
		Vulnerabilities []struct {
			Severity string `json:"severity"`
			Location struct {
				File      string `json:"file"`
				StartLine int    `json:"start_line"`
			} `json:"location"`
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
		} `json:"vulnerabilities"`
	}

	var s securityReport
	read(sast, &s)
	if s.Scan.Type != "sast" || s.Scan.Status != "success" || len(s.Vulnerabilities) != 1 {
		t.Fatalf("SAST report: type=%q status=%q vulnerabilities=%d", s.Scan.Type, s.Scan.Status, len(s.Vulnerabilities))
	}
	v := s.Vulnerabilities[0]
	if v.Severity != "High" || v.Location.File != "app.py" || v.Location.StartLine != 2 ||
		len(v.Identifiers) == 0 || v.Identifiers[0].Type != "fakescan_rule_id" || v.Identifiers[0].Value != "cmd-injection" {
		t.Errorf("vulnerability = %+v", v)
	}
	if s.Scan.Scanner.Version == "" {
		t.Error("the schema requires a scanner version, also in a development build")
	}
	// The scan's real start and end, in the zone-less UTC form the schema demands.
	const layout = "2006-01-02T15:04:05"
	start, err1 := time.Parse(layout, s.Scan.StartTime)
	end, err2 := time.Parse(layout, s.Scan.EndTime)
	if err1 != nil || err2 != nil || start.Before(before.Truncate(time.Second)) || end.After(after) || end.Before(start) {
		t.Errorf("times %q .. %q are not this run's (between %s and %s)", s.Scan.StartTime, s.Scan.EndTime, before, after)
	}

	// No credential finding: a valid report with an empty list, not a missing file.
	var sd securityReport
	read(secrets, &sd)
	if sd.Scan.Type != "secret_detection" || sd.Vulnerabilities == nil || len(sd.Vulnerabilities) != 0 {
		t.Errorf("secret detection report: type=%q vulnerabilities=%v", sd.Scan.Type, sd.Vulnerabilities)
	}

	var issues []struct {
		CheckName string `json:"check_name"`
		Severity  string `json:"severity"`
		Location  struct {
			Path string `json:"path"`
		} `json:"location"`
	}
	read(quality, &issues)
	if len(issues) != 1 || issues[0].CheckName != "cmd-injection" || issues[0].Severity != "critical" || issues[0].Location.Path != "app.py" {
		t.Errorf("Code Quality report = %+v", issues)
	}
}

func TestScannedCommit(t *testing.T) {
	t.Setenv("CI_COMMIT_SHA", "from-gitlab")
	if got := scannedCommit(&options{}); got != "from-gitlab" {
		t.Errorf("in GitLab CI the commit comes from CI_COMMIT_SHA, got %q", got)
	}
	if got := scannedCommit(&options{sourceCommit: "explicit"}); got != "explicit" {
		t.Errorf("--source-commit must win, got %q", got)
	}
}

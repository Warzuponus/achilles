package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Warzuponus/achilles/internal/eval"
)

// runOWASP scans an OWASP Benchmark (Java or Python) checkout with achilles and scores the
// result against its answer key, the way the Benchmark's own scorecard does.
// Achilles runs exactly as a user would run it, so ACHILLES_SETTINGS (for example
// "mode: commercial") and ACHILLES_HOME apply.
//
// With sarifIn set, no scan runs: that report, written by any tool, is scored
// instead. That is how other scanners are compared on the same terms
// (docs/comparison.md).
func runOWASP(dir, sarifIn, achillesBin, cacheDir, out string, timeout time.Duration) error {
	if dir == "" {
		return errors.New("--mode owasp needs --owasp-dir: a checkout of github.com/OWASP-Benchmark/BenchmarkJava or BenchmarkPython")
	}
	keys, _ := filepath.Glob(filepath.Join(dir, "expectedresults-*.csv"))
	if len(keys) != 1 {
		return fmt.Errorf("%s: want exactly one expectedresults-*.csv, found %d", dir, len(keys))
	}
	f, err := os.Open(keys[0]) // #nosec G304 -- the answer key in the checkout the operator named
	if err != nil {
		return err
	}
	cases, err := eval.ParseOWASPExpected(f)
	_ = f.Close()
	if err != nil {
		return err
	}
	// BenchmarkJava keeps its cases in the Java package tree, BenchmarkPython in
	// testcode/ at the root.
	var testcode string
	for _, c := range []string{
		filepath.Join(dir, "src", "main", "java", "org", "owasp", "benchmark", "testcode"),
		filepath.Join(dir, "testcode"),
	} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			testcode = c
			break
		}
	}
	if testcode == "" {
		return fmt.Errorf("%s: no testcode directory (is this a BenchmarkJava or BenchmarkPython checkout?)", dir)
	}

	sarif := sarifIn
	if sarif == "" {
		work, err := os.MkdirTemp("", "achilles-owasp-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(work)
		sarif = filepath.Join(work, "report.sarif")
		if err := scanOWASP(testcode, work, sarif, achillesBin, cacheDir, len(cases), timeout); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(os.Stderr, "achilles-eval: owasp — scoring %s against %d test cases\n", sarifIn, len(cases))
	}
	sf, err := os.Open(sarif) // #nosec G304 -- our own temp file, or the report the operator named
	if err != nil {
		return fmt.Errorf("no SARIF report: %w", err)
	}
	flags, err := eval.OWASPFlags(sf)
	_ = sf.Close()
	if err != nil {
		return err
	}
	res := eval.OWASPScore(cases, flags)
	eval.WriteOWASPScorecard(os.Stdout, res)
	fmt.Println("\nSCORE is true-positive rate minus false-positive rate, the Benchmark scorecard's measure: 0 is guessing, 100 is perfect.")
	fmt.Println("The Benchmark counts a finding only when its CWE is the category's; the last column also accepts closely related CWEs.")
	if out != "" {
		b, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// scanOWASP runs achilles over the Benchmark's test cases, writing SARIF to sarif.
func scanOWASP(testcode, work, sarif, achillesBin, cacheDir string, n int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	bin, err := locateAchilles(ctx, achillesBin, cacheDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "achilles-eval: owasp — scanning %d test cases with %s\n", n, bin)
	cmd := exec.CommandContext(ctx, bin, "--vault", filepath.Join(work, "vault.json"), "--sarif-report", sarif, testcode) // #nosec G204 -- operator-chosen binary, fixed flags
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		// Exit 1 means findings at or above --fail-on: the expected outcome here.
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			return fmt.Errorf("achilles: %w", err)
		}
	}
	return nil
}

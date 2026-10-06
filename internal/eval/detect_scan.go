package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// ScanRequest is one run of the scanner over a target directory.
type ScanRequest struct {
	// Dir is the absolute scan root.
	Dir string
	// KeepDismissed asks achilles not to move AI-dismissed findings out of the
	// reported set (--keep-dismissed), so the pass shows what the scanners found
	// before the AI review filtered anything.
	KeepDismissed bool
	// AI turns the LLM review on for this pass.
	AI bool
}

// ScanOutput is everything the benchmark needs from one run. It is deliberately
// the artifacts achilles itself writes — the SARIF report and the Evidence Vault —
// rather than anything the benchmark computes, so the loss-point analysis reads the
// same record an auditor would.
type ScanOutput struct {
	// Findings are the results the report surfaces; Dismissed are the ones it
	// carries as suppressed (AI-dismissed). Paths are as reported.
	Findings  []model.Finding
	Dismissed []model.Finding
	// Records is the run's Evidence Vault.
	Records []vault.Record
	// Log is the tail of the scanner's stderr, for diagnosing a failed run.
	Log string
	// ExitNote is set when achilles exited non-zero but still wrote its report.
	ExitNote string
}

// ScanRunner runs a scan and returns what it produced. The real implementation
// executes the achilles binary; tests supply a fake, which keeps every unit test
// hermetic (no scanners, no network, no keys).
type ScanRunner interface {
	RunScan(ctx context.Context, req ScanRequest) (ScanOutput, error)
}

// BinaryScanRunner runs the real achilles binary.
type BinaryScanRunner struct {
	// Bin is the achilles executable.
	Bin string
	// Args are passed on every run (e.g. --exclude, --config, --diff).
	Args []string
	// AIArgs are added to runs with AI set (--triage, --llm-*).
	AIArgs []string
	// Timeout bounds one run; also passed to achilles as --timeout.
	Timeout time.Duration
}

// RunScan implements ScanRunner.
func (b BinaryScanRunner) RunScan(ctx context.Context, req ScanRequest) (ScanOutput, error) {
	work, err := os.MkdirTemp("", "achilles-detect-*")
	if err != nil {
		return ScanOutput{}, err
	}
	defer os.RemoveAll(work)
	vaultPath := filepath.Join(work, "vault.jsonl")
	sarifPath := filepath.Join(work, "report.sarif")

	args := []string{"--vault", vaultPath, "--sarif-report", sarifPath}
	if b.Timeout > 0 {
		args = append(args, "--timeout", b.Timeout.String())
	}
	if req.KeepDismissed {
		args = append(args, "--keep-dismissed")
	}
	args = append(args, b.Args...)
	if req.AI {
		args = append(args, b.AIArgs...)
	}
	args = append(args, req.Dir) // positional target last: flag parsing stops at the first non-flag

	runCtx := ctx
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, b.Timeout+time.Minute)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, b.Bin, args...) // #nosec G204 -- operator-chosen binary, fixed flags
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = nil // the human report is not needed; SARIF and the vault are
	runErr := cmd.Run()
	log := tail(stderr.String(), 3000)

	data, readErr := os.ReadFile(sarifPath) // #nosec G304 -- our own temp dir
	if readErr != nil {
		if runErr != nil {
			return ScanOutput{Log: log}, fmt.Errorf("achilles failed before writing a report: %w\n%s", runErr, log)
		}
		return ScanOutput{Log: log}, fmt.Errorf("achilles wrote no SARIF report: %w", readErr)
	}
	out := ScanOutput{Log: log}
	if runErr != nil {
		out.ExitNote = runErr.Error()
	}
	if out.Findings, out.Dismissed, err = parseSARIFReport(data); err != nil {
		return out, err
	}
	if st, serr := os.Stat(vaultPath); serr == nil && st.Size() > 0 {
		fs, ferr := vault.NewFileStore(vaultPath)
		if ferr != nil {
			return out, fmt.Errorf("read scan vault: %w", ferr)
		}
		out.Records = fs.All()
	}
	return out, nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// parseSARIFReport reads achilles's own --sarif-report output into surfaced and
// suppressed (AI-dismissed) findings.
func parseSARIFReport(data []byte) (surfaced, dismissed []model.Finding, err error) {
	var log model.SarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, nil, fmt.Errorf("parse SARIF report: %w", err)
	}
	for _, run := range log.Runs {
		for _, r := range run.Results {
			f := model.Finding{
				RuleID:  r.RuleID,
				Message: r.Message.Text,
			}
			f.Fingerprint = r.Fingerprints["achilles/v1"]
			if len(r.Locations) > 0 {
				pl := r.Locations[0].PhysicalLocation
				f.Location.File = pl.ArtifactLocation.URI
				f.Location.Region.StartLine = pl.Region.StartLine
				f.Location.Region.EndLine = pl.Region.EndLine
			}
			if cwes, ok := r.Properties["cwe"].([]any); ok {
				for _, c := range cwes {
					if s, ok := c.(string); ok {
						f.CWE = append(f.CWE, s)
					}
				}
			}
			if cls, ok := r.Properties["achilles/verdict"].(string); ok {
				v := &model.Verdict{Classification: model.Classification(cls)}
				if c, ok := r.Properties["achilles/confidence"].(float64); ok {
					v.Confidence = c
				}
				f.Verdict = v
			}
			if len(r.Suppressions) > 0 {
				if f.Verdict == nil {
					f.Verdict = &model.Verdict{}
				}
				f.Verdict.Reasoning = r.Suppressions[0].Justification
				dismissed = append(dismissed, f)
				continue
			}
			surfaced = append(surfaced, f)
		}
	}
	return surfaced, dismissed, nil
}

// ToolFailure is a scanner that did not produce results.
type ToolFailure struct {
	Tool  string `json:"tool"`
	Stage string `json:"stage"` // run | normalize
	Error string `json:"error"`
	// Missing is true when the failure is "the binary is not installed".
	Missing bool `json:"missing,omitempty"`
}

// scanFacts is what a pass's artifacts say about how the scan went.
type scanFacts struct {
	HasVault   bool
	Registered []string
	Ran        []string
	Failed     []ToolFailure
	Skipped    []string
	// Candidates are every finding the scanners reported, before the noise/diff/
	// baseline filters (achilles records findings to the vault before filtering).
	Candidates []model.Finding
	// Verdicts are the AI verdicts by finding fingerprint (last record wins).
	Verdicts       map[string]model.Verdict
	NoiseExcluded  int
	BaselineUsed   bool
	TargetRecorded string
}

// isMissingBinary recognizes the "tool is not installed" failures.
func isMissingBinary(msg string) bool {
	l := strings.ToLower(msg)
	return strings.Contains(l, "executable file not found") ||
		strings.Contains(l, "not found in $path") ||
		strings.Contains(l, "on path (it shells out")
}

// digest reads a vault into scanFacts. Absent or partial vaults yield HasVault
// false rather than an error: the analysis then says what it could not see.
func digest(records []vault.Record) scanFacts {
	f := scanFacts{Verdicts: map[string]model.Verdict{}}
	ran := map[string]bool{}
	failed := map[string]bool{}
	for _, r := range records {
		switch r.Kind {
		case vault.KindScanMeta:
			var p map[string]json.RawMessage
			if json.Unmarshal(r.Payload, &p) != nil {
				continue
			}
			switch r.Source {
			case "":
				var tools []string
				_ = json.Unmarshal(p["tools"], &tools)
				if len(tools) > 0 {
					f.Registered = tools
					f.HasVault = true
				}
				_ = json.Unmarshal(p["target"], &f.TargetRecorded)
			case "diagnostics":
				var fails []ToolFailure
				_ = json.Unmarshal(p["parseFailures"], &fails)
				for _, tf := range fails {
					tf.Missing = isMissingBinary(tf.Error)
					f.Failed = append(f.Failed, tf)
					failed[tf.Tool] = true
				}
			case "noise":
				var n int
				_ = json.Unmarshal(p["excluded"], &n)
				f.NoiseExcluded += n
			case "baseline":
				f.BaselineUsed = true
			}
		case vault.KindRawOutput:
			ran[r.Source] = true
		case vault.KindFinding:
			var fnd model.Finding
			if json.Unmarshal(r.Payload, &fnd) != nil {
				continue
			}
			// The registry id (the record's source) is what tool status and the
			// capability table are keyed on; the payload's tool is a display name.
			if r.Source != "" {
				fnd.Tool = r.Source
			}
			f.Candidates = append(f.Candidates, fnd)
		case vault.KindVerdict:
			var v model.Verdict
			if json.Unmarshal(r.Payload, &v) == nil && r.Fingerprint != "" {
				f.Verdicts[r.Fingerprint] = v
			}
		}
	}
	for t := range ran {
		f.Ran = append(f.Ran, t)
	}
	sort.Strings(f.Ran)
	sort.Slice(f.Failed, func(i, j int) bool { return f.Failed[i].Tool < f.Failed[j].Tool })
	for _, t := range f.Registered {
		if !ran[t] && !failed[t] {
			f.Skipped = append(f.Skipped, t)
		}
	}
	sort.Strings(f.Skipped)
	return f
}

// enrichFromVault fills in what the SARIF report drops: the originating tool, the
// end line, and the full verdict (SARIF carries only classification+confidence).
func enrichFromVault(fs []model.Finding, cands []model.Finding, verdicts map[string]model.Verdict, roots []string) {
	key := func(f model.Finding) string {
		return fmt.Sprintf("%s|%s|%d", f.RuleID, normalizeFindingPath(f.Location.File, roots), f.Location.Region.StartLine)
	}
	byKey := map[string]model.Finding{}
	for _, c := range cands {
		if _, dup := byKey[key(c)]; !dup {
			byKey[key(c)] = c
		}
	}
	for i := range fs {
		if c, ok := byKey[key(fs[i])]; ok {
			fs[i].Tool = c.Tool
			if fs[i].Location.Region.EndLine == 0 {
				fs[i].Location.Region.EndLine = c.Location.Region.EndLine
			}
			if fs[i].Fingerprint == "" {
				fs[i].Fingerprint = c.Fingerprint
			}
			if len(fs[i].CWE) == 0 {
				fs[i].CWE = c.CWE
			}
		}
		if v, ok := verdicts[fs[i].Fingerprint]; ok {
			vv := v
			fs[i].Verdict = &vv
		}
	}
}

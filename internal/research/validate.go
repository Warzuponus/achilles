package research

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/normalize"
	"github.com/Warzuponus/achilles/internal/scanner"
	"github.com/Warzuponus/achilles/internal/scanner/opengrep"
)

// Validator runs a generated rule against its fixtures. Split out as an
// interface so the engine's admit/quarantine logic is testable with a fake and
// the real (opengrep-backed) validator is exercised by an integration test.
type Validator interface {
	Validate(ctx context.Context, r GeneratedRule) (ValidationResult, error)
}

// Admit is the §9.3 gate: a rule ships ONLY if it parses, matches the
// vulnerable fixture, does NOT match the patched fixture, and does NOT match
// ordinary unrelated code. This is the whole idea — a rule that can't catch the
// bug without flagging the fix is quarantined.
func Admit(res ValidationResult) (bool, string) {
	switch {
	case !res.Parses:
		return false, "rule does not parse/compile in the engine"
	case !res.MatchesVulnerable:
		return false, "rule does not match the vulnerable fixture (no true-positive proof)"
	case res.MatchesPatched:
		return false, "rule also matches the patched fixture (false-positive proof)"
	case res.MatchesControl:
		return false, "rule also matches ordinary, unrelated code: it is too broad to be a detection"
	default:
		return true, "passed validation gate"
	}
}

// FixtureProblem returns why a rule's own fixtures cannot prove anything, or "".
//
// The gate asks one model for a rule, a vulnerable example and a patched example,
// then checks the rule against those examples. Two degenerate answers passed it: an
// empty patched example (nothing to match, so "does not match the patched code" is
// vacuously true for any rule, including `pattern: $F(...)`), and a patched example
// identical to the vulnerable one.
func FixtureProblem(r GeneratedRule) string {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	vuln, patched := norm(r.VulnerableSnippet), norm(r.PatchedSnippet)
	switch {
	case strings.TrimSpace(r.RuleYAML) == "":
		return "the rule is empty"
	case vuln == "":
		return "no vulnerable fixture: nothing shows the rule finds the issue"
	case patched == "":
		return "no patched fixture: nothing shows the rule leaves fixed code alone"
	case vuln == patched:
		return "the patched fixture is the same as the vulnerable one: it shows nothing"
	}
	return ""
}

// Judge runs the whole admission gate for one rule and says whether to admit it.
func Judge(ctx context.Context, v Validator, r GeneratedRule) (res ValidationResult, admit bool, reason string) {
	if p := FixtureProblem(r); p != "" {
		return ValidationResult{Detail: p}, false, p
	}
	res, err := v.Validate(ctx, r)
	if err != nil {
		return res, false, fmt.Sprintf("validation error: %v", err)
	}
	admit, reason = Admit(res)
	return res, admit, reason
}

// controlSnippets are small pieces of ordinary code, one per language, with
// nothing security-relevant in them: an import, a function, an assignment, a
// call, a loop, a condition. A rule that fires on one of these is matching the
// shape of code in general (`$F(...)`, `$X = $Y`), not the issue it was written
// for. The model that wrote the rule never sees them.
var controlSnippets = map[string]string{
	"python":     "import math\n\n\ndef area(radius):\n    total = math.pi * radius * radius\n    return round(total, 2)\n\n\nnames = [\"a\", \"b\"]\nfor name in names:\n    if name:\n        print(name.upper())\n",
	"javascript": "const path = require('path');\n\nfunction area(radius) {\n  const total = Math.PI * radius * radius;\n  return Math.round(total);\n}\n\nconst names = ['a', 'b'];\nfor (const name of names) {\n  if (name) {\n    console.log(name.toUpperCase());\n  }\n}\nmodule.exports = { area, base: path.basename('a/b') };\n",
	"typescript": "import * as path from 'path';\n\nexport function area(radius: number): number {\n  const total = Math.PI * radius * radius;\n  return Math.round(total);\n}\n\nconst names: string[] = ['a', 'b'];\nfor (const name of names) {\n  if (name) {\n    console.log(name.toUpperCase(), path.basename('a/b'));\n  }\n}\n",
	"go":         "package control\n\nimport (\n\t\"fmt\"\n\t\"strings\"\n)\n\nfunc Area(radius float64) float64 {\n\ttotal := 3.14159 * radius * radius\n\treturn total\n}\n\nfunc Names() {\n\tnames := []string{\"a\", \"b\"}\n\tfor _, name := range names {\n\t\tif name != \"\" {\n\t\t\tfmt.Println(strings.ToUpper(name))\n\t\t}\n\t}\n}\n",
	"ruby":       "require 'set'\n\ndef area(radius)\n  total = 3.14159 * radius * radius\n  total.round(2)\nend\n\nnames = Set.new(%w[a b])\nnames.each do |name|\n  puts name.upcase if name\nend\n",
	"java":       "import java.util.List;\n\npublic class Control {\n    static double area(double radius) {\n        double total = Math.PI * radius * radius;\n        return Math.round(total);\n    }\n\n    public static void main(String[] args) {\n        List<String> names = List.of(\"a\", \"b\");\n        for (String name : names) {\n            if (!name.isEmpty()) {\n                System.out.println(name.toUpperCase());\n            }\n        }\n    }\n}\n",
	"php":        "<?php\n\nfunction area(float $radius): float {\n    $total = M_PI * $radius * $radius;\n    return round($total, 2);\n}\n\n$names = ['a', 'b'];\nforeach ($names as $name) {\n    if ($name) {\n        echo strtoupper($name), \"\\n\";\n    }\n}\n",
	"csharp":     "using System;\nusing System.Collections.Generic;\n\npublic static class Control\n{\n    public static double Area(double radius)\n    {\n        var total = Math.PI * radius * radius;\n        return Math.Round(total, 2);\n    }\n\n    public static void Main()\n    {\n        var names = new List<string> { \"a\", \"b\" };\n        foreach (var name in names)\n        {\n            if (name.Length > 0)\n            {\n                Console.WriteLine(name.ToUpper());\n            }\n        }\n    }\n}\n",
}

var langExt = map[string]string{
	"python": ".py", "javascript": ".js", "typescript": ".ts", "go": ".go",
	"ruby": ".rb", "java": ".java", "php": ".php", "csharp": ".cs",
}

func extFor(lang string) string {
	if e, ok := langExt[lang]; ok {
		return e
	}
	return ".txt"
}

// OpengrepValidator validates rules by actually running Opengrep on synthetic
// fixtures in a sandbox (DESIGN.md §9.5: only ever runs synthetic snippets).
type OpengrepValidator struct {
	runner xexec.Runner
}

func NewOpengrepValidator(runner xexec.Runner) *OpengrepValidator {
	return &OpengrepValidator{runner: runner}
}

func (v *OpengrepValidator) Validate(ctx context.Context, r GeneratedRule) (ValidationResult, error) {
	base, err := os.MkdirTemp("", "achilles-validate-*")
	if err != nil {
		return ValidationResult{}, err
	}
	defer os.RemoveAll(base)

	rulesDir := filepath.Join(base, "rules")
	vulnDir := filepath.Join(base, "vuln")
	patchedDir := filepath.Join(base, "patched")
	controlDir := filepath.Join(base, "control")
	for _, d := range []string{rulesDir, vulnDir, patchedDir, controlDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return ValidationResult{}, err
		}
	}
	ext := extFor(r.Language)
	if err := os.WriteFile(filepath.Join(rulesDir, "rule.yaml"), []byte(r.RuleYAML), 0o644); err != nil {
		return ValidationResult{}, err
	}
	if err := os.WriteFile(filepath.Join(vulnDir, "case"+ext), []byte(r.VulnerableSnippet), 0o644); err != nil {
		return ValidationResult{}, err
	}
	if err := os.WriteFile(filepath.Join(patchedDir, "case"+ext), []byte(r.PatchedSnippet), 0o644); err != nil {
		return ValidationResult{}, err
	}

	vc, ok1 := v.matchCount(ctx, rulesDir, vulnDir)
	pc, ok2 := v.matchCount(ctx, rulesDir, patchedDir)

	// Ordinary code in the same language, which the rule's author never saw. A
	// language with no control snippet is not checked this way.
	cc := 0
	if control, ok := controlSnippets[r.Language]; ok && ok1 && ok2 {
		if err := os.WriteFile(filepath.Join(controlDir, "control"+ext), []byte(control), 0o644); err != nil {
			return ValidationResult{}, err
		}
		cc, _ = v.matchCount(ctx, rulesDir, controlDir)
	}

	return ValidationResult{
		Parses:            ok1 && ok2,
		MatchesVulnerable: vc > 0,
		MatchesPatched:    pc > 0,
		MatchesControl:    cc > 0,
		Detail:            fmt.Sprintf("vuln matches=%d patched matches=%d control matches=%d", vc, pc, cc),
	}, nil
}

// matchCount runs Opengrep with the rule over a code dir. ok=false means the
// rule failed to parse/run (Opengrep errored), which the gate treats as no-parse.
func (v *OpengrepValidator) matchCount(ctx context.Context, rulesDir, codeDir string) (int, bool) {
	sc := opengrep.New(v.runner, rulesDir)
	raw, err := sc.Run(ctx, scanner.Target{Path: codeDir})
	if err != nil {
		return 0, false
	}
	findings, err := normalize.FromSARIF(raw.Tool, raw.Data)
	if err != nil {
		return 0, false
	}
	return len(findings), true
}

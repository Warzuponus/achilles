package main

import (
	"path/filepath"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// ownOutputs are the places inside the scanned directory where Achilles keeps
// what it wrote: its state directory (the Evidence Vault, the baseline, generated
// rules) and the reports of this run.
//
// They have to be left out of the next scan. The vault records each finding with
// the code around it, and the reports quote it, so a scanner that reads every file
// finds the same issue again in them: once in the code, once more in the vault, and
// one more time for every run. Unlike the noise filter this is not optional
// (--no-default-excludes does not turn it off): these files are Achilles' output,
// not the project's code.
func ownOutputs(o *options, absTarget string) (dirs, files map[string]bool) {
	dirs, files = map[string]bool{".achilles": true}, map[string]bool{}
	add := func(p string, dir bool) {
		if rel, ok := insideTarget(absTarget, p); ok {
			if dir {
				dirs[rel] = true
			} else {
				files[rel] = true
			}
		}
	}
	if o.vaultBackend == "" || o.vaultBackend == "file" {
		add(o.vaultPath, false)
		add(o.vaultPath+".lock", false)
	}
	if o.aiOn {
		add(o.reportDir, true)
	}
	for _, p := range []string{o.sarifReport, o.jsonReport, o.junitOut, o.markdownOut, o.htmlReport, o.diagnostics,
		o.sbomOut, o.threatModelOut, o.gitlabSAST, o.gitlabSecrets, o.gitlabDeps, o.gitlabCodeQuality, o.writeBl} {
		add(p, false)
	}
	if o.sarifOut != "" {
		add(o.sarifOut, true)
	}
	return dirs, files
}

// dropOwnOutputs removes findings located in Achilles' own state or reports and
// returns how many it removed.
func dropOwnOutputs(o *options, absTarget string, scan *model.Scan) int {
	dirs, files := ownOutputs(o, absTarget)
	kept := scan.Findings[:0:0]
	dropped := 0
	for _, f := range scan.Findings {
		rel := filepath.ToSlash(f.Location.File)
		if filepath.IsAbs(f.Location.File) {
			if r, ok := insideTarget(absTarget, f.Location.File); ok {
				rel = r
			}
		}
		rel = strings.TrimPrefix(rel, "./")
		if files[rel] || underAny(rel, dirs) {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	scan.Findings = kept
	return dropped
}

func underAny(rel string, dirs map[string]bool) bool {
	for d := range dirs {
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

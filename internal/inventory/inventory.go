// Package inventory detects a codebase's languages and declared dependencies —
// the "Recon" input that seeds the research agents (DESIGN.md §9.2 step 1).
package inventory

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Dependency is a declared third-party package.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string // "go" | "pypi" | "npm"
}

// Inventory is what Recon discovers about a target.
type Inventory struct {
	Languages    []string
	Dependencies []Dependency
	// LongPaths counts files whose full path is MaxPathChars characters or more,
	// and LongPathExample names the first one. Windows programs that are not
	// built for long paths (Opengrep among them) cannot open such files, and skip
	// them without an error.
	LongPaths       int
	LongPathExample string
}

// MaxPathChars is Windows' MAX_PATH: a full path of this many characters or more
// cannot be opened by a program that does not opt in to long paths.
const MaxPathChars = 260

var extLang = map[string]string{
	".go": "go", ".py": "python", ".js": "javascript", ".jsx": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".rb": "ruby", ".java": "java",
	".php": "php", ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".rs": "rust",
	".sh": "shell", ".bash": "shell",
}

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, ".venv": true,
	"venv": true, "dist": true, "build": true, ".achilles": true,
}

// Scan walks root and returns detected languages and dependencies. Best-effort:
// unreadable manifests are skipped rather than failing the scan.
func Scan(root string) (Inventory, error) {
	langs := map[string]bool{}
	var deps []Dependency
	var long int
	var longExample string
	if abs, aerr := filepath.Abs(root); aerr == nil {
		root = abs
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if l, ok := extLang[strings.ToLower(filepath.Ext(d.Name()))]; ok {
			langs[l] = true
		}
		if len(path) >= MaxPathChars {
			if long == 0 {
				longExample = path
			}
			long++
		}
		switch d.Name() {
		case "go.mod":
			deps = append(deps, parseGoMod(path)...)
		case "requirements.txt":
			deps = append(deps, parseRequirements(path)...)
		case "package.json":
			deps = append(deps, parsePackageJSON(path)...)
		}
		return nil
	})
	if err != nil {
		return Inventory{}, err
	}

	out := Inventory{Languages: keys(langs), Dependencies: deps, LongPaths: long, LongPathExample: longExample}
	return out, nil
}

var goModRE = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9._/-]+)\s+(v[0-9][^\s]*)`)

func parseGoMod(path string) []Dependency {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var deps []Dependency
	for _, m := range goModRE.FindAllStringSubmatch(string(data), -1) {
		deps = append(deps, Dependency{Name: m[1], Version: m[2], Ecosystem: "go"})
	}
	return deps
}

var reqRE = regexp.MustCompile(`(?m)^([A-Za-z0-9._-]+)\s*(?:==|>=|~=|<=)\s*([0-9][^\s;#]*)`)

func parseRequirements(path string) []Dependency {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var deps []Dependency
	for _, m := range reqRE.FindAllStringSubmatch(string(data), -1) {
		deps = append(deps, Dependency{Name: m[1], Version: m[2], Ecosystem: "pypi"})
	}
	return deps
}

func parsePackageJSON(path string) []Dependency {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var deps []Dependency
	for _, set := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, ver := range set {
			deps = append(deps, Dependency{Name: name, Version: strings.TrimLeft(ver, "^~>=<v "), Ecosystem: "npm"})
		}
	}
	return deps
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

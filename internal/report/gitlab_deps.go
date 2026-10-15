package report

import (
	"encoding/json"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// The dependency scanning report (artifacts:reports:dependency_scanning) carries
// the dependency advisories, which the SAST report leaves out. GitLab's format
// wants each one tied to a package and a version in a manifest or lock file.

type glDepReport struct {
	Version         string          `json:"version"`
	Schema          string          `json:"schema"`
	Scan            glScan          `json:"scan"`
	Vulnerabilities []glDepVuln     `json:"vulnerabilities"`
	DependencyFiles []glDepFile     `json:"dependency_files"`
	Remediations    []glRemediation `json:"remediations,omitempty"`
}

type glDepVuln struct {
	ID          string              `json:"id"`
	Name        string              `json:"name,omitempty"`
	Description string              `json:"description,omitempty"`
	Severity    string              `json:"severity"`
	Solution    string              `json:"solution,omitempty"`
	Location    glDepLocation       `json:"location"`
	Identifiers []glIdentifier      `json:"identifiers"`
	Flags       []glFlag            `json:"flags,omitempty"`
	Details     map[string]glDetail `json:"details,omitempty"`
}

type glDepLocation struct {
	File       string       `json:"file"`
	Dependency glDependency `json:"dependency"`
}

type glDependency struct {
	Package glPackage `json:"package"`
	Version string    `json:"version"`
}

type glPackage struct {
	Name string `json:"name"`
}

type glDepFile struct {
	Path           string         `json:"path"`
	PackageManager string         `json:"package_manager"`
	Dependencies   []glDependency `json:"dependencies"`
}

// unknownDependency stands in for a package or version an advisory does not
// name: the format requires both, and an advisory is not dropped for lack of them.
const unknownDependency = "unknown"

// The package and version, as osv-scanner and Trivy write them into an
// advisory's message:
//
//	osv-scanner: Package 'pyyaml@5.3.1' is vulnerable to 'CVE-2020-14343' ...
//	Trivy:       Package: PyYAML\nInstalled Version: 5.3.1\n...
var (
	osvPackage   = regexp.MustCompile(`Package '(.+)@([^@']+)' is vulnerable`)
	trivyPackage = regexp.MustCompile(`(?m)^Package: *(\S.*?)\s*$`)
	trivyVersion = regexp.MustCompile(`(?m)^Installed Version: *(\S.*?)\s*$`)
	trivyFixed   = regexp.MustCompile(`(?m)^Fixed Version: *(\S.*?)\s*$`)
)

// advisoryPackage returns the package an advisory is about, and the version
// that fixes it when the scanner says.
func advisoryPackage(f model.Finding) (dep glDependency, fixed string) {
	dep = glDependency{Package: glPackage{Name: unknownDependency}, Version: unknownDependency}
	if m := osvPackage.FindStringSubmatch(f.Message); m != nil {
		dep.Package.Name, dep.Version = m[1], m[2]
		return dep, ""
	}
	if m := trivyPackage.FindStringSubmatch(f.Message); m != nil {
		dep.Package.Name = m[1]
		if v := trivyVersion.FindStringSubmatch(f.Message); v != nil {
			dep.Version = v[1]
		}
		if fx := trivyFixed.FindStringSubmatch(f.Message); fx != nil {
			fixed = fx[1]
		}
	}
	return dep, fixed
}

// packageManagers names the package manager behind a manifest or lock file.
var packageManagers = map[string]string{
	"requirements.txt": "pip", "pipfile.lock": "pipenv", "poetry.lock": "poetry", "uv.lock": "uv",
	"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm",
	"go.mod": "go", "go.sum": "go",
	"gemfile.lock": "bundler", "composer.lock": "composer", "cargo.lock": "cargo",
	"pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle", "gradle.lockfile": "gradle",
	"packages.lock.json": "nuget", "mix.lock": "hex", "pubspec.lock": "pub",
}

func packageManager(file string) string {
	base := strings.ToLower(path.Base(file))
	if pm, ok := packageManagers[base]; ok {
		return pm
	}
	if strings.HasSuffix(base, ".csproj") {
		return "nuget"
	}
	return unknownDependency
}

// WriteGitLabDependencyScanning writes the dependency advisories (osv-scanner,
// Trivy, and any finding that names an advisory) as a GitLab dependency scanning
// report.
func WriteGitLabDependencyScanning(w io.Writer, s model.Scan, meta GitLabMeta) error {
	doc := glDepReport{
		Version:         GitLabSchemaVersion,
		Schema:          gitlabSchemaBase + "dependency-scanning-report-format.json",
		Scan:            gitlabScanHeader(s, meta, "dependency_scanning"),
		Vulnerabilities: []glDepVuln{}, // arrays even when empty: null does not validate
		DependencyFiles: []glDepFile{},
	}
	files := map[string]*glDepFile{}
	listed := map[string]bool{}
	seen := map[string]int{}
	for _, f := range s.Findings {
		if f.Shadow || !f.IsDependencyAdvisory() {
			continue
		}
		base := gitlabVuln(f, seen)
		dep, fixed := advisoryPackage(f)
		file := base.Location.File
		if file == "" {
			file = gitlabPath(f.Location.File)
		}
		if file == "" {
			file = "." // the format wants a path; the advisory was not tied to one
		}
		v := glDepVuln{
			ID: base.ID, Name: base.Name, Description: base.Description, Severity: base.Severity,
			Solution: base.Solution, Identifiers: base.Identifiers, Flags: base.Flags, Details: base.Details,
			Location: glDepLocation{File: file, Dependency: dep},
		}
		if v.Solution == "" && fixed != "" {
			v.Solution = gitlabText("Upgrade "+dep.Package.Name+" to "+fixed+" or later.", gitlabMaxSolution)
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)

		df := files[file]
		if df == nil {
			df = &glDepFile{Path: file, PackageManager: packageManager(file), Dependencies: []glDependency{}}
			files[file] = df
		}
		if key := file + "\x00" + dep.Package.Name + "\x00" + dep.Version; !listed[key] {
			listed[key] = true
			df.Dependencies = append(df.Dependencies, dep)
		}
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		doc.DependencyFiles = append(doc.DependencyFiles, *files[p])
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

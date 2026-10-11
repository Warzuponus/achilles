package verifyfix

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// CheckFix decides whether a model-written remediation diff may be applied for a
// finding in file (a path relative to the scan target). It is the gate every diff
// passes before `git apply`, whether or not the re-scan runs, because a diff that
// goes into a pull request is code a model wrote after reading text an attacker
// may have written.
//
// On top of the structural checks (size, no binary or symlink changes, no path
// that escapes the tree) it enforces scope:
//
//   - the diff may modify the finding's own file and nothing else. The
//     remediation prompt shows the model that one file, so a change anywhere else
//     is code it invented without seeing, and it is how a "fix" for a flagged line
//     would also add a workflow step, a build target or a dependency;
//   - it may not create, delete, rename or copy a file;
//   - it may never touch a path that runs on its own in CI or on checkout
//     (workflows, pipeline definitions, git hooks and attributes, submodule
//     pointers), even when that is where the finding is. Those are fixed by hand.
func CheckFix(diff, file string) error {
	if err := checkDiff(diff, DefaultMaxDiffBytes, DefaultMaxDiffFiles); err != nil {
		return err
	}
	return checkScope(diff, file)
}

func checkScope(diff, file string) error {
	file = cleanRel(file)
	if file == "" {
		return fmt.Errorf("the finding has no file, so the fix has no place it may change")
	}
	if why := sensitivePath(file); why != "" {
		return fmt.Errorf("%s is %s; fixes there are not applied automatically", file, why)
	}

	touched := map[string]bool{}
	for _, line := range strings.Split(diff, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "new file mode"), strings.HasPrefix(line, "deleted file mode"):
			return fmt.Errorf("the fix creates or deletes a file; only edits to %s are accepted", file)
		case strings.HasPrefix(line, "rename from "), strings.HasPrefix(line, "rename to "),
			strings.HasPrefix(line, "copy from "), strings.HasPrefix(line, "copy to "):
			return fmt.Errorf("the fix renames or copies a file; only edits to %s are accepted", file)
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			p := line[4:]
			if i := strings.IndexByte(p, '\t'); i >= 0 {
				p = p[:i]
			}
			if p == "/dev/null" {
				return fmt.Errorf("the fix creates or deletes a file; only edits to %s are accepted", file)
			}
			touched[applyPath(p)] = true
		case strings.HasPrefix(line, "old mode "), strings.HasPrefix(line, "new mode "):
			return fmt.Errorf("the fix changes a file's mode; only edits to the contents of %s are accepted", file)
		case strings.HasPrefix(line, "diff --git "):
			p, ok := gitHeaderPath(line[len("diff --git "):])
			if !ok {
				return fmt.Errorf("the fix's %q header names two different files; only edits to %s are accepted", "diff --git", file)
			}
			touched[p] = true
		}
	}

	if touched[""] {
		return fmt.Errorf("the fix names a path with no a/ b/ prefix, so which file it patches is ambiguous; only edits to %s are accepted", file)
	}
	var outside []string
	for p := range touched {
		if p != file {
			outside = append(outside, p)
		}
	}
	if len(outside) > 0 {
		sort.Strings(outside)
		return fmt.Errorf("the fix touches %s, outside the finding's file %s", strings.Join(outside, ", "), file)
	}
	if !touched[file] {
		return fmt.Errorf("the fix does not change the finding's file %s", file)
	}
	return nil
}

// gitHeaderPath reads the one file a "diff --git <old> <new>" header names. The two
// names are separated by a space and may themselves contain spaces, so the header
// is split at each " " in turn until both halves name the same file after -p1. A
// header whose halves never agree names two files (a rename or a copy), which is
// out of scope.
func gitHeaderPath(rest string) (string, bool) {
	for i := 0; i < len(rest); i++ {
		if rest[i] != ' ' {
			continue
		}
		left, right := applyPath(rest[:i]), applyPath(rest[i+1:])
		if left != "" && left == right {
			return left, true
		}
	}
	return "", false
}

// applyPath is the path `git apply` will actually write for a header path: it
// strips the first component (-p1), whatever that component is called. Comparing
// anything else would check one path and patch another.
//
// A header path with no directory component has nothing to strip. Left to itself
// git would guess the strip level from the files on disk, so the same diff could
// patch different files in different trees; gitops.Apply passes -p1 to rule that
// out, and such a path is reported here as "" (never the finding's file).
func applyPath(p string) string {
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return cleanRel(p[i+1:])
	}
	return ""
}

func cleanRel(p string) string {
	p = strings.TrimSpace(filepath.ToSlash(p))
	if p == "" {
		return ""
	}
	return strings.TrimPrefix(path.Clean(p), "./")
}

// sensitivePath reports why a path must never be changed by an automatic fix, or
// "" if it may be. These are files that execute, or decide what executes, without
// anyone running them: a pull request that edits one runs the edit.
func sensitivePath(file string) string {
	lower := strings.ToLower(file)
	segs := strings.Split(lower, "/")
	base := segs[len(segs)-1]

	for _, s := range segs[:len(segs)-1] {
		switch s {
		case ".github", ".gitlab", ".circleci", ".buildkite", ".husky", ".githooks", ".devcontainer", ".woodpecker", ".teamcity":
			return "CI or repository automation (" + s + "/)"
		}
	}
	switch base {
	case ".gitmodules", ".gitattributes", ".gitconfig",
		".gitlab-ci.yml", ".travis.yml", ".drone.yml", ".woodpecker.yml", ".pre-commit-config.yaml",
		"azure-pipelines.yml", "bitbucket-pipelines.yml", "jenkinsfile", "cloudbuild.yaml", "buildspec.yml", "appveyor.yml":
		return "a CI or git control file"
	}
	return ""
}

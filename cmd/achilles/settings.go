package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Settings files are flags written down: a flat YAML mapping from a flag's name
// (without the dashes) to its value. A list is the same as a comma-separated value.
//
//	profile: full
//	fail-on: high
//	exclude: [tests, "*.gen.go"]
//
// Two files can supply them, and they are trusted differently.
//
// --settings FILE is chosen by whoever runs Achilles. It is trusted exactly as the
// command line is and may set any flag.
//
// .achilles.yaml in the root of the scanned directory arrives with the code under
// review, and a pull request can change it. It may therefore only shape the scan of
// that code (repoSettingKeys). It can never say where code is sent, which model
// reads it, which programs run, what is written outside the repository or what is
// posted anywhere: those are the operator's decisions. What it does set is named
// on stderr and recorded in the reports, the same way the scanners' own repository
// configuration is, and --no-repo-config ignores the file altogether.
//
// Precedence: command line, then --settings, then .achilles.yaml, then defaults.

// repoSettingsNames are the names the repository's own settings file may have.
var repoSettingsNames = []string{".achilles.yaml", ".achilles.yml"}

// maxSettingsBytes bounds a settings file. A real one is a few hundred bytes.
const maxSettingsBytes = 1 << 20

// repoSettingKeys are the flags the scanned repository may set for itself. Every
// one of them is about how this code is scanned and gated. Nothing here chooses an
// endpoint, a model, a credential mode, a program to run, an output path or an
// action on GitHub, and nothing here turns on a feature that sends code anywhere
// or spends money.
var repoSettingKeys = map[string]bool{
	"profile":             true, // which set of scanners
	"exclude":             true, // paths that are noise in this repository
	"no-default-excludes": true,
	"fail-on":             true, // the gate, when the operator did not set one
	"baseline":            true, // a baseline file inside the repository
	"timeout":             true, // how long this repository's scanners need
	"keep-dismissed":      true,
	"llm-no-code":         true, // a repository may ask for more privacy, never less
	"issues-min-severity": true,
	"issues-max":          true,
	"issues-group":        true,
}

// settingsUse is what one settings file contributed to the run.
type settingsUse struct {
	File       string
	Applied    []string // keys taken from the file
	Overridden []string // keys in the file that something more trusted had already set
}

// parseSettings reads a settings document into flag name -> value, as the value
// would be typed on the command line.
func parseSettings(data []byte) (map[string]string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc))
	for key, v := range doc {
		s, err := settingValue(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out[key] = s
	}
	return out, nil
}

func settingValue(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "", errors.New("has no value")
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case int:
		return strconv.Itoa(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			if _, nested := item.([]any); nested {
				return "", errors.New("a list may only hold plain values")
			}
			s, err := settingValue(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ","), nil
	default:
		return "", errors.New("must be a plain value or a list of them")
	}
}

// applySettings sets the flags named in values, except those in taken (already
// set by something more trusted). allowed, when not nil, is the only set of keys
// the file may use. adjust, when not nil, may rewrite or reject a value before it
// is set. Keys that were applied are added to taken.
func applySettings(fl *flag.FlagSet, file string, values map[string]string, allowed, taken map[string]bool, adjust func(key, value string) (string, error)) (*settingsUse, error) {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	use := &settingsUse{File: file}
	for _, key := range keys {
		value := values[key]
		if fl.Lookup(key) == nil || key == "settings" {
			return nil, fmt.Errorf("%s: unknown setting %q (a setting is a flag's name without the dashes; `achilles --help` lists them)", file, key)
		}
		if allowed != nil && !allowed[key] {
			return nil, fmt.Errorf("%s: %q cannot be set by the scanned repository. Its own settings file may only shape the scan (%s); pass --%s on the command line or in a --settings file",
				file, key, strings.Join(sortedKeys(allowed), ", "), key)
		}
		if taken[key] {
			use.Overridden = append(use.Overridden, key)
			continue
		}
		if adjust != nil {
			adjusted, err := adjust(key, value)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", file, key, err)
			}
			value = adjusted
		}
		if err := fl.Set(key, value); err != nil {
			return nil, fmt.Errorf("%s: %s: %q is not a valid value (%v)", file, key, values[key], err)
		}
		taken[key] = true
		use.Applied = append(use.Applied, key)
	}
	return use, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readRepoSettings returns the scanned repository's own settings file; name is
// empty when it has none. The file is opened inside the target and must be a
// regular file: a symbolic link here would have Achilles read, and quote in its
// error messages, whatever file on the operator's machine the repository chose.
func readRepoSettings(target string) (data []byte, name string, err error) {
	root, err := os.OpenRoot(target)
	if err != nil {
		return nil, "", nil // not a directory, or not there: the scan itself reports that
	}
	defer root.Close()
	for _, candidate := range repoSettingsNames {
		st, err := root.Lstat(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", candidate, err)
		}
		if name != "" {
			return nil, "", fmt.Errorf("the scanned repository has both %s and %s; keep one", name, candidate)
		}
		if !st.Mode().IsRegular() {
			return nil, "", fmt.Errorf("%s in the scanned repository is not a regular file; refusing to read it", candidate)
		}
		if st.Size() > maxSettingsBytes {
			return nil, "", fmt.Errorf("%s in the scanned repository is %d bytes; a settings file is at most %d", candidate, st.Size(), maxSettingsBytes)
		}
		f, err := root.Open(candidate)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", candidate, err)
		}
		data, err = io.ReadAll(io.LimitReader(f, maxSettingsBytes))
		_ = f.Close()
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", candidate, err)
		}
		name = candidate
	}
	return data, name, nil
}

// loadSettings applies --settings and then the scanned repository's own file.
// taken holds the flags given on the command line and grows with every flag a
// file sets.
func (o *options) loadSettings(fl *flag.FlagSet, taken map[string]bool) error {
	if o.settingsPath != "" {
		data, err := os.ReadFile(o.settingsPath)
		if err != nil {
			return fmt.Errorf("--settings: %w", err)
		}
		values, err := parseSettings(data)
		if err != nil {
			return fmt.Errorf("--settings %s: %w", o.settingsPath, err)
		}
		if o.settings, err = applySettings(fl, o.settingsPath, values, nil, taken, nil); err != nil {
			return err
		}
	}
	// Commands that scan nothing have no repository to take settings from.
	if o.showVersion || o.feedbackFP != "" || o.ruleHealth || o.metricsOn || o.fromSarif != "" {
		return nil
	}
	data, name, err := readRepoSettings(o.target)
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	if o.noRepoConfig {
		o.repoSettingsIgnored = name
		return nil
	}
	values, err := parseSettings(data)
	if err != nil {
		return fmt.Errorf("%s in the scanned repository: %w", name, err)
	}
	// A path in the repository's file is relative to the repository, and stays in it.
	inRepo := func(key, value string) (string, error) {
		if key != "baseline" {
			return value, nil
		}
		rel := filepath.FromSlash(value)
		if !filepath.IsLocal(rel) {
			return "", fmt.Errorf("%q must be a path inside the scanned repository", value)
		}
		return filepath.Join(o.target, rel), nil
	}
	o.repoSettings, err = applySettings(fl, name, values, repoSettingKeys, taken, inRepo)
	return err
}

// announceSettings says which settings files shaped the run. The repository's own
// file is never applied silently.
func (o *options) announceSettings(w io.Writer) {
	if s := o.settings; s != nil && len(s.Applied) > 0 {
		fmt.Fprintf(w, "achilles: settings from %s: %s\n", s.File, strings.Join(s.Applied, ", "))
	}
	if o.repoSettingsIgnored != "" {
		fmt.Fprintf(w, "achilles: --no-repo-config: ignoring %s from the scanned repository\n", o.repoSettingsIgnored)
	}
	s := o.repoSettings
	if s == nil {
		return
	}
	if len(s.Applied) > 0 {
		fmt.Fprintf(w, "achilles: %s in the scanned repository sets %s (--no-repo-config to ignore it)\n", s.File, strings.Join(s.Applied, ", "))
	}
	if len(s.Overridden) > 0 {
		fmt.Fprintf(w, "achilles: %s in the scanned repository also sets %s, which the command line or --settings already decided\n", s.File, strings.Join(s.Overridden, ", "))
	}
}

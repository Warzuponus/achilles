package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/configs"
	"github.com/Warzuponus/achilles/internal/toolchain"
)

// embeddedRulesPath is how configs/tools.yaml spells the baseline rules dir.
const embeddedRulesPath = "configs/rules"

const (
	maxOverlayFiles = 500
	maxOverlayBytes = 1 << 20 // per file
)

// ResolveRulesDir turns a tool config's `rules:` value into a real host
// directory (Opengrep needs a directory for `-f`). Precedence:
//
//  1. p names an existing directory on disk (a repo checkout, a custom rules
//     dir, a --config that ships its own rules) -> that directory, absolute.
//     Nothing is merged: an on-disk rules dir is taken as the complete rule set.
//  2. p is the default "configs/rules" but it does not exist on disk (a
//     downloaded binary run outside a checkout) -> the rules embedded in the
//     binary, materialized into a content-addressed cache directory
//     (os.UserCacheDir()/achilles/rules-<sha256 prefix>). If
//     $ACHILLES_HOME/rules (see toolchain.RulesDir) holds extra *.yaml/*.yml
//     files they are merged in under user/ and are part of the cache key.
//  3. anything else -> the absolute path as given (the scan then fails loudly
//     when the tool cannot read it, as before).
func ResolveRulesDir(p string) (string, error) {
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return filepath.Abs(p)
	}
	if filepath.ToSlash(filepath.Clean(p)) == embeddedRulesPath {
		return materializeRules()
	}
	return filepath.Abs(p)
}

// collectRules gathers the embedded rule files plus the optional user overlay,
// keyed by slash-separated path relative to the rules root.
func collectRules() (map[string][]byte, error) {
	files := map[string][]byte{}
	err := fs.WalkDir(configs.FS, "rules", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := configs.FS.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		files[strings.TrimPrefix(p, "rules/")] = b
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read embedded rules: %w", err)
	}
	if len(files) == 0 {
		return nil, errors.New("no rules embedded in this binary")
	}

	// Optional overlay. Regular *.yaml/*.yml files only; symlinks are ignored.
	if dir, derr := toolchain.RulesDir(); derr == nil {
		ents, rerr := os.ReadDir(dir)
		n := 0
		for _, e := range ents {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if rerr != nil || !e.Type().IsRegular() || (ext != ".yaml" && ext != ".yml") {
				continue
			}
			if n++; n > maxOverlayFiles {
				break
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil || len(b) > maxOverlayBytes {
				continue
			}
			files["user/"+e.Name()] = b
		}
	}
	return files, nil
}

func rulesKey(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func materializeRules() (string, error) {
	files, err := collectRules()
	if err != nil {
		return "", err
	}
	key := rulesKey(files)

	root, err := os.UserCacheDir()
	if err == nil {
		root = filepath.Join(root, "achilles")
		err = os.MkdirAll(root, 0o700)
	}
	if err != nil {
		// No usable cache dir (e.g. HOME unset): fall back to a private temp dir
		// for this run. It is not reused, so it is not content-addressed.
		tmp, terr := os.MkdirTemp("", "achilles-rules-*")
		if terr != nil {
			return "", fmt.Errorf("materialize embedded rules: %w", terr)
		}
		return tmp, writeRules(tmp, files)
	}

	dest := filepath.Join(root, "rules-"+key)
	if rulesDirMatches(dest, files) {
		return dest, nil
	}

	// Write beside the destination, then rename: readers never see a half-written
	// directory, and concurrent first runs race harmlessly.
	tmp, err := os.MkdirTemp(root, ".rules-tmp-*")
	if err != nil {
		return "", fmt.Errorf("materialize embedded rules: %w", err)
	}
	defer os.RemoveAll(tmp) // no-op after a successful rename
	if err := writeRules(tmp, files); err != nil {
		return "", err
	}
	if _, serr := os.Lstat(dest); serr == nil {
		// Present but failed verification (tampered or partial): replace it.
		os.RemoveAll(dest)
	}
	if err := os.Rename(tmp, dest); err != nil {
		if rulesDirMatches(dest, files) { // lost a race to an identical writer
			return dest, nil
		}
		return "", fmt.Errorf("materialize embedded rules: %w", err)
	}
	return dest, nil
}

func writeRules(dir string, files map[string][]byte) error {
	for name, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// rulesDirMatches reports whether dir holds exactly the expected files with the
// expected contents (no extras, no symlinks) — a cached dir is trusted only after
// this check, since a rules dir decides what the scanner looks for.
func rulesDirMatches(dir string, want map[string][]byte) bool {
	got := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("unexpected non-regular file")
		}
		rel, _ := filepath.Rel(dir, p)
		exp, ok := want[filepath.ToSlash(rel)]
		if !ok {
			return errors.New("unexpected file")
		}
		b, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(b, exp) {
			return errors.New("content differs")
		}
		got++
		return nil
	})
	return err == nil && got == len(want)
}

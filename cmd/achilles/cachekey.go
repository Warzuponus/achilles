package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Warzuponus/achilles/internal/toolchain"
)

// verdictCacheKeyFile is the name of the signing key in the Achilles home
// directory ($ACHILLES_HOME, default ~/.achilles).
const verdictCacheKeyFile = "verdict-cache.key"

// verdictCacheSecret returns the key that signs verdict-cache entries, creating it
// on first use.
//
// The key is what makes a cached verdict trustworthy (see internal/triage/cache.go):
// it lives in the user's Achilles home, never in the vault and never in a scanned
// directory, so a vault file that arrives with a repository cannot contain entries
// that verify. A different machine, or a fresh CI runner, has a different key and
// simply starts with an empty cache.
func verdictCacheSecret() ([]byte, error) {
	home, err := toolchain.Home()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, verdictCacheKeyFile)
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- a fixed file name under the user's own Achilles home
		return decodeCacheSecret(b, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	// O_EXCL: if another run created the key in the meantime, use that one, so two
	// concurrent runs do not end up signing with different keys.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- as above
	if errors.Is(err, os.ErrExist) {
		b, rerr := os.ReadFile(path) // #nosec G304 -- as above
		if rerr != nil {
			return nil, rerr
		}
		return decodeCacheSecret(b, path)
	}
	if err != nil {
		return nil, err
	}
	_, werr := f.WriteString(hex.EncodeToString(raw) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return nil, werr
	}
	return raw, nil
}

func decodeCacheSecret(b []byte, path string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) < 16 {
		return nil, fmt.Errorf("%s is not a valid verdict-cache key; delete it to have a new one created", path)
	}
	return raw, nil
}

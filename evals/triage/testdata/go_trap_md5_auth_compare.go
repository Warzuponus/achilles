package cases

import (
	"crypto/md5"
	"encoding/hex"
)

// cacheKey returns a hex digest of the given value.
func cacheKey(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// authenticate reports whether the supplied password matches the stored digest.
func authenticate(password, storedDigest string) bool {
	return cacheKey(password) == storedDigest
}

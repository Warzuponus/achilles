package cases

import (
	"crypto/md5"
	"encoding/hex"
)

// cacheKey returns the in-process cache key for a rendered page URL.
func cacheKey(url string) string {
	sum := md5.Sum([]byte(url))
	return "page:" + hex.EncodeToString(sum[:])
}

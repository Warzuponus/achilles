package cases

import (
	"crypto/md5"
	"encoding/hex"
)

// hashPassword derives the stored representation of a user's password.
func hashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

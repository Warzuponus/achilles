package cases

import (
	"fmt"
	"math/rand"
)

// sessionToken returns the token stored in a logged-in user's session cookie.
func sessionToken() string {
	return fmt.Sprintf("%016x", rand.Uint64())
}

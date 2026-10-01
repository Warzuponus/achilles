package cases

import (
	"math/rand"
	"time"
)

// retryDelay returns the backoff delay before the given retry attempt.
func retryDelay(attempt int) time.Duration {
	base := time.Duration(attempt) * time.Second
	return base + time.Duration(rand.Intn(500))*time.Millisecond
}

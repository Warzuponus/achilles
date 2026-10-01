package fleet

import (
	"context"
	"time"
)

// Every runs fn repeatedly, waiting interval between the END of one run and the
// START of the next (so runs never overlap), until ctx is cancelled. fn receives
// ctx so an in-flight dispatch is cancelled promptly on shutdown. It runs fn once
// immediately; if ctx is already cancelled it runs nothing.
func Every(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	for ctx.Err() == nil {
		fn(ctx)
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

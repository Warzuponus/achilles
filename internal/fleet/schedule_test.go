package fleet

import (
	"context"
	"testing"
	"time"
)

func TestEvery_RepeatsUntilCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		Every(ctx, 10*time.Millisecond, func(c context.Context) {
			if c != ctx {
				t.Error("fn must receive the loop context so in-flight work is cancelled on shutdown")
			}
			runs++
			if runs == 3 {
				cancel()
			}
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Every did not stop after cancel")
	}
	if runs != 3 {
		t.Errorf("runs = %d, want 3", runs)
	}
}

func TestEvery_NoRunWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Every(ctx, time.Hour, func(context.Context) { t.Error("must not run") })
}

func TestEvery_StopsPromptlyDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Every(ctx, time.Hour, func(context.Context) { cancel() }) // cancel during the first run
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Every blocked on the interval instead of honoring cancel")
	}
}

func TestEvery_RunsDoNotOverlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	active, maxActive, runs := 0, 0, 0
	Every(ctx, time.Millisecond, func(context.Context) {
		active++
		if active > maxActive {
			maxActive = active
		}
		time.Sleep(5 * time.Millisecond)
		active--
		if runs++; runs == 3 {
			cancel()
		}
	})
	if maxActive != 1 {
		t.Errorf("runs overlapped: %d", maxActive)
	}
}

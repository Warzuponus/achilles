package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const okBody = `{"model":"m","choices":[{"finish_reason":"stop","message":{"content":"{\"ok\":true}"}}]}`

// A dropped connection is the most ordinary transient failure there is. Only a
// handful of HTTP statuses were retried; anything without a status was final.
func TestRetry_DroppedConnectionIsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close() // no response at all: the client sees EOF or a reset
			}
			return
		}
		io.WriteString(w, okBody)
	}))
	defer srv.Close()

	cl := NewOpenAI(srv.URL, "", "m")
	var waits []time.Duration
	cl.sleep = noSleep(&waits)
	resp, err := cl.Complete(context.Background(), Request{Messages: userMsg})
	if err != nil {
		t.Fatalf("a dropped connection followed by a good reply must succeed: %v", err)
	}
	if calls.Load() != 2 || len(waits) != 1 || !strings.Contains(resp.Content, "ok") {
		t.Errorf("calls=%d waits=%v content=%q", calls.Load(), waits, resp.Content)
	}
}

func TestRetry_ResponseCutOffMidBodyIsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Length", "500") // promise more than is sent
			io.WriteString(w, `{"model":"m","choices":[`)
			return
		}
		io.WriteString(w, okBody)
	}))
	defer srv.Close()

	cl := NewOpenAI(srv.URL, "", "m")
	cl.sleep = noSleep(new([]time.Duration))
	if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
		t.Fatalf("a reply cut off mid-body must be retried, not decoded: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
}

func TestRetry_ServerErrorsAndTimeoutsAreTransient(t *testing.T) {
	for _, status := range []int{500, 408, 529} {
		srv, n := retryServer(t, []int{status}, "")
		cl := NewOpenAI(srv.URL, "", "m")
		cl.sleep = noSleep(new([]time.Duration))
		if _, err := cl.Complete(context.Background(), Request{Messages: userMsg}); err != nil {
			t.Errorf("HTTP %d then success: %v", status, err)
		}
		if *n != 2 {
			t.Errorf("HTTP %d: calls = %d, want 2", status, *n)
		}
	}
}

func TestRetryAfter_SecondsAndHTTPDate(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                              0,
		"7":                             7 * time.Second,
		"0":                             0,
		"-3":                            0,
		"soon":                          0,
		"Sun, 11 Oct 2026 12:00:30 GMT": 30 * time.Second,
		"Sun, 11 Oct 2026 11:59:00 GMT": 0, // already past
	}
	for h, want := range cases {
		if got := retryAfter(h, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestJitter_StaysInTheUpperHalfAndVaries(t *testing.T) {
	const d = 4 * time.Second
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		j := jitter(d)
		if j < d/2 || j > d {
			t.Fatalf("jitter(%v) = %v, outside [%v, %v]", d, j, d/2, d)
		}
		seen[j] = true
	}
	if len(seen) < 20 {
		t.Errorf("jitter produced only %d distinct waits in 200 tries", len(seen))
	}
	if jitter(0) != 0 {
		t.Error("jitter(0) must be 0")
	}
}

// truncatingClient answers every call with a reply that stops at the output limit.
type truncatingClient struct{ calls int }

func (c *truncatingClient) Complete(context.Context, Request) (Response, error) {
	c.calls++
	return Response{Content: `{"classification":"true_positive","reasoning":"the value flows from the req`, Truncated: true}, nil
}

// A reply cut off at max_tokens does not parse, so it looked like malformed JSON
// and earned a repair request, which was cut off at the same limit.
func TestCompleteAndDecode_TruncatedReplyIsNotRepaired(t *testing.T) {
	c := &truncatingClient{}
	var out struct {
		Classification string `json:"classification"`
	}
	_, err := CompleteAndDecode(context.Background(), c, userMsg, nil, &out, nil)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
	if !strings.Contains(err.Error(), "ACHILLES_LLM_MAX_TOKENS") {
		t.Errorf("the error must say how to fix it: %v", err)
	}
	if c.calls != 1 {
		t.Errorf("made %d calls; a repair request cannot fix a cut-off reply", c.calls)
	}
}

func TestComplete_ReportsTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"model":"m","choices":[{"finish_reason":"length","message":{"content":"{\"a\":"}}]}`)
	}))
	defer srv.Close()
	resp, err := NewOpenAI(srv.URL, "", "m").Complete(context.Background(), Request{Messages: userMsg})
	if err != nil || !resp.Truncated {
		t.Errorf("Truncated = %v, err = %v; finish_reason \"length\" must be reported", resp.Truncated, err)
	}
}

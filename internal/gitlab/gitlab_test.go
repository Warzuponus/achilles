package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGitLab is just enough of the notes API: one merge request, its notes, and
// the token's own user.
type fakeGitLab struct {
	mu        sync.Mutex
	me        int64
	notes     []Note
	nextID    int64
	posts     int
	puts      int
	tokens    []string
	paths     []string
	failNext  int // respond 500 to the next n requests
	limitNext int // respond 429 to the next n requests
}

func (f *fakeGitLab) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokens = append(f.tokens, r.Header.Get("PRIVATE-TOKEN"))
		f.paths = append(f.paths, r.Method+" "+r.URL.EscapedPath())
		if f.limitNext > 0 {
			f.limitNext--
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if f.failNext > 0 {
			f.failNext--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		const notes = "/api/v4/projects/group%2Fproj/merge_requests/7/notes"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v4/user":
			fmt.Fprintf(w, `{"id":%d,"username":"achilles-bot"}`, f.me)
		case r.Method == http.MethodGet && r.URL.EscapedPath() == notes:
			json.NewEncoder(w).Encode(f.notes)
		case r.Method == http.MethodPost && r.URL.EscapedPath() == notes:
			var b struct{ Body string }
			data, _ := io.ReadAll(r.Body)
			json.Unmarshal(data, &b)
			f.nextID++
			n := Note{ID: f.nextID, Body: b.Body}
			n.Author.ID = f.me
			f.notes = append(f.notes, n)
			f.posts++
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(n)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.EscapedPath(), notes+"/"):
			var b struct{ Body string }
			data, _ := io.ReadAll(r.Body)
			json.Unmarshal(data, &b)
			id := strings.TrimPrefix(r.URL.EscapedPath(), notes+"/")
			for i := range f.notes {
				if fmt.Sprint(f.notes[i].ID) == id {
					f.notes[i].Body = b.Body
				}
			}
			f.puts++
			w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newClient(t *testing.T, f *fakeGitLab) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	c, err := New("glpat-test", "group/proj", srv.URL+"/api/v4")
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestUpsertMergeRequestNote_CreatesThenUpdates(t *testing.T) {
	f := &fakeGitLab{me: 42}
	c := newClient(t, f)
	ctx := context.Background()

	created, err := c.UpsertMergeRequestNote(ctx, 7, "mr-summary", "first run")
	if err != nil || !created {
		t.Fatalf("first upsert: created=%v err=%v; want a new note", created, err)
	}
	created, err = c.UpsertMergeRequestNote(ctx, 7, "mr-summary", "second run")
	if err != nil || created {
		t.Fatalf("second upsert: created=%v err=%v; want the note updated", created, err)
	}
	if f.posts != 1 || f.puts != 1 || len(f.notes) != 1 {
		t.Fatalf("posts=%d puts=%d notes=%d; want one note, posted once and updated once", f.posts, f.puts, len(f.notes))
	}
	if !strings.HasPrefix(f.notes[0].Body, "<!-- achilles:mr-summary -->\n") || !strings.HasSuffix(f.notes[0].Body, "second run") {
		t.Errorf("note body = %q", f.notes[0].Body)
	}
	for _, tok := range f.tokens {
		if tok != "glpat-test" {
			t.Errorf("request sent PRIVATE-TOKEN %q", tok)
		}
	}
}

// A note that carries the marker but was written by someone else is never
// adopted: its author could rewrite it between runs.
func TestUpsertMergeRequestNote_IgnoresAStrangersMarker(t *testing.T) {
	f := &fakeGitLab{me: 42, nextID: 100}
	planted := Note{ID: 5, Body: "<!-- achilles:mr-summary -->\nnothing to see here"}
	planted.Author.ID = 9
	quoted := Note{ID: 6, Body: "as the bot said: <!-- achilles:mr-summary -->"}
	quoted.Author.ID = 42
	f.notes = []Note{planted, quoted}
	c := newClient(t, f)

	created, err := c.UpsertMergeRequestNote(context.Background(), 7, "mr-summary", "findings")
	if err != nil || !created {
		t.Fatalf("created=%v err=%v; want a new note of our own", created, err)
	}
	if f.notes[0].Body != planted.Body {
		t.Error("the stranger's note was overwritten")
	}
}

func TestUpsertMergeRequestNote_RetriesRateLimitsButNeverRepostsAfterAServerError(t *testing.T) {
	f := &fakeGitLab{me: 42, limitNext: 1}
	c := newClient(t, f)
	if _, err := c.UpsertMergeRequestNote(context.Background(), 7, "mr-summary", "x"); err != nil {
		t.Fatalf("a single 429 should be retried: %v", err)
	}

	// A POST that fails with 500 may still have created the note: not retried.
	f2 := &fakeGitLab{me: 42}
	c2 := newClient(t, f2)
	// /user and the listing go through; the POST fails.
	c2.HTTP = &http.Client{Transport: postFails{rt: http.DefaultTransport}}
	if _, err := c2.UpsertMergeRequestNote(context.Background(), 7, "mr-summary", "x"); err == nil {
		t.Fatal("want the server error reported")
	}
	if f2.posts != 0 {
		t.Errorf("posts = %d after a failed POST; want no retry", f2.posts)
	}
}

// postFails answers every POST with a 500 without passing it on.
type postFails struct{ rt http.RoundTripper }

func (f postFails) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost {
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("boom")), Header: http.Header{}, Request: r}, nil
	}
	return f.rt.RoundTrip(r)
}

func TestNew_RefusesToSendTheTokenInTheClear(t *testing.T) {
	if _, err := New("t", "1", "http://gitlab.example.com/api/v4"); err == nil {
		t.Error("an http API URL on a remote host was accepted")
	}
	if _, err := New("t", "1", "http://127.0.0.1:8080/api/v4"); err != nil {
		t.Errorf("a loopback test server was refused: %v", err)
	}
	if _, err := New("", "1", ""); err == nil {
		t.Error("no token was accepted")
	}
	if _, err := New("t", " ", ""); err == nil {
		t.Error("no project was accepted")
	}
	c, err := New("t", "1", "")
	if err != nil || c.BaseURL != DefaultBaseURL {
		t.Errorf("default base URL = %q, %v", c.BaseURL, err)
	}
}

func TestTruncateKeepsNotesUnderTheLimit(t *testing.T) {
	long := strings.Repeat("a line of the report\n", MaxNoteBytes/10)
	got := truncate(long)
	if len(got) > MaxNoteBytes+200 {
		t.Errorf("truncated note is %d bytes", len(got))
	}
	if !strings.Contains(got, "cut to fit") {
		t.Error("truncated note does not say it was cut")
	}
	if truncate("short") != "short" {
		t.Error("a short note was changed")
	}
}

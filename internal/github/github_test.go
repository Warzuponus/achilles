package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New("tok", "acme/app", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
	c.CreatePause = 0 // tests never wait
	return c
}

func TestNew_Validation(t *testing.T) {
	if _, err := New("", "a/b", ""); err == nil {
		t.Error("empty token should error")
	}
	if _, err := New("t", "noslash", ""); err == nil {
		t.Error("repo without owner/name should error")
	}
	c, err := New("t", "acme/app", "")
	if err != nil || c.Owner != "acme" || c.Repo != "app" || c.BaseURL != "https://api.github.com" {
		t.Errorf("New parsed wrong: %+v err=%v", c, err)
	}
}

func TestUpsertComment_Create(t *testing.T) {
	var posted string
	var gotAuth, gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/app/issues/7/comments":
			io.WriteString(w, `[{"id":1,"body":"unrelated"}]`) // no achilles marker
		case r.Method == "POST" && r.URL.Path == "/repos/acme/app/issues/7/comments":
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			json.Unmarshal(b, &m)
			posted = m["body"]
			io.WriteString(w, `{"id":99}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	created, err := newTestClient(t, srv).UpsertComment(context.Background(), 7, "pr-summary", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("expected created=true when no prior comment")
	}
	if !strings.Contains(posted, "<!-- achilles:pr-summary -->") || !strings.Contains(posted, "hello") {
		t.Errorf("posted body wrong: %q", posted)
	}
	if gotAuth != "Bearer tok" || gotVersion != "2022-11-28" {
		t.Errorf("headers wrong: auth=%q version=%q", gotAuth, gotVersion)
	}
}

func TestUpsertComment_UpdateExisting(t *testing.T) {
	var patchedPath, patchedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			// An existing Achilles comment (id 42) carries the marker.
			io.WriteString(w, `[{"id":41,"body":"someone else"},{"id":42,"body":"<!-- achilles:pr-summary -->\nold"}]`)
		case r.Method == "PATCH":
			patchedPath = r.URL.Path
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			json.Unmarshal(b, &m)
			patchedBody = m["body"]
			io.WriteString(w, `{"id":42}`)
		default:
			t.Errorf("unexpected %s %s (should PATCH, not POST)", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	created, err := newTestClient(t, srv).UpsertComment(context.Background(), 7, "pr-summary", "new body")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("expected created=false when updating an existing sticky comment")
	}
	if patchedPath != "/repos/acme/app/issues/comments/42" {
		t.Errorf("patched wrong comment: %q", patchedPath)
	}
	if !strings.Contains(patchedBody, "new body") {
		t.Errorf("patch body wrong: %q", patchedBody)
	}
}

func TestCreateReviewComment(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/repos/acme/app/pulls/7/comments" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":1}`)
	}))
	defer srv.Close()

	err := newTestClient(t, srv).CreateReviewComment(context.Background(), 7, "deadbeef", "src/main.go", 12, "watch out")
	if err != nil {
		t.Fatal(err)
	}
	if got["commit_id"] != "deadbeef" || got["path"] != "src/main.go" || got["side"] != "RIGHT" || got["line"].(float64) != 12 {
		t.Errorf("review comment payload wrong: %+v", got)
	}
}

func TestListPullComments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/app/pulls/7/comments" {
			t.Errorf("path %s", r.URL.Path)
		}
		io.WriteString(w, `[{"id":1,"body":"<!-- achilles:fp:abc123 -->\nold"}]`)
	}))
	defer srv.Close()
	cs, err := newTestClient(t, srv).ListPullComments(context.Background(), 7)
	if err != nil || len(cs) != 1 || !strings.Contains(cs[0].Body, "fp:abc123") {
		t.Errorf("list pull comments wrong: %+v err=%v", cs, err)
	}
}

func TestListIssues_FiltersPRs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/app/issues" || r.URL.Query().Get("labels") != "achilles" || r.URL.Query().Get("state") != "all" {
			t.Errorf("wrong request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		// One real issue (open), one closed, and one PR (pull_request set) to be filtered.
		io.WriteString(w, `[{"number":1,"state":"open","body":"<!-- achilles:fp:aaa -->"},
			{"number":2,"state":"closed","body":"<!-- achilles:fp:bbb -->"},
			{"number":3,"state":"open","body":"x","pull_request":{"url":"y"}}]`)
	}))
	defer srv.Close()
	is, err := newTestClient(t, srv).ListIssues(context.Background(), "achilles")
	if err != nil {
		t.Fatal(err)
	}
	if len(is) != 2 || is[0].Number != 1 || is[1].Number != 2 {
		t.Errorf("expected 2 non-PR issues, got %+v", is)
	}
}

func TestCreateIssue(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/repos/acme/app/issues" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{"number":77}`)
	}))
	defer srv.Close()
	num, err := newTestClient(t, srv).CreateIssue(context.Background(), "title", "body", []string{"achilles"})
	if err != nil || num != 77 {
		t.Fatalf("CreateIssue num=%d err=%v", num, err)
	}
	if got["title"] != "title" || got["body"] != "body" {
		t.Errorf("payload wrong: %+v", got)
	}
	if labels, _ := got["labels"].([]any); len(labels) != 1 || labels[0] != "achilles" {
		t.Errorf("labels wrong: %+v", got["labels"])
	}
}

func TestCloseIssue_CommentsThenCloses(t *testing.T) {
	var commented, closed bool
	var stateReason string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/repos/acme/app/issues/5/comments":
			commented = true
			io.WriteString(w, `{"id":1}`)
		case r.Method == "PATCH" && r.URL.Path == "/repos/acme/app/issues/5":
			closed = true
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			json.Unmarshal(b, &m)
			stateReason = m["state"] + "/" + m["state_reason"]
			io.WriteString(w, `{"number":5}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	if err := newTestClient(t, srv).CloseIssue(context.Background(), 5, "done"); err != nil {
		t.Fatal(err)
	}
	if !commented || !closed || stateReason != "closed/completed" {
		t.Errorf("commented=%v closed=%v stateReason=%q", commented, closed, stateReason)
	}
}

func TestCreatePull(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/repos/acme/app/pulls" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"number":12,"html_url":"https://github.com/acme/app/pull/12"}`)
	}))
	defer srv.Close()
	pr, err := newTestClient(t, srv).CreatePull(context.Background(), "title", "achilles/autofix-abc", "main", "body")
	if err != nil || pr.Number != 12 || !strings.Contains(pr.HTMLURL, "/pull/12") {
		t.Fatalf("CreatePull pr=%+v err=%v", pr, err)
	}
	if got["head"] != "achilles/autofix-abc" || got["base"] != "main" || got["title"] != "title" {
		t.Errorf("payload wrong: %+v", got)
	}
}

func TestListPullsForHead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/app/pulls" || r.URL.Query().Get("head") != "acme:achilles/autofix-abc" || r.URL.Query().Get("state") != "open" {
			t.Errorf("wrong request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		io.WriteString(w, `[{"number":9,"state":"open","head":{"ref":"achilles/autofix-abc"}}]`)
	}))
	defer srv.Close()
	pulls, err := newTestClient(t, srv).ListPullsForHead(context.Background(), "achilles/autofix-abc")
	if err != nil || len(pulls) != 1 || pulls[0].Number != 9 {
		t.Errorf("ListPullsForHead=%+v err=%v", pulls, err)
	}
}

func TestDo_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv).UpsertComment(context.Background(), 7, "pr-summary", "x")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected a 403 error surfaced, got %v", err)
	}
}

func TestListIssues_Pagination(t *testing.T) {
	var srv *httptest.Server
	calls := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", `<`+srv.URL+`/repos/acme/app/issues?page=2>; rel="next", <`+srv.URL+`/x?page=3>; rel="last"`)
			io.WriteString(w, `[{"number":1,"state":"open","labels":[{"name":"achilles"}]}]`)
		case "2":
			w.Header().Set("Link", `<`+srv.URL+`/repos/acme/app/issues?page=3>; rel="next"`)
			io.WriteString(w, `[{"number":2,"state":"closed"},{"number":9,"state":"open","pull_request":{}}]`)
		case "3":
			io.WriteString(w, `[{"number":3,"state":"open"}]`)
		}
	}))
	defer srv.Close()
	is, err := newTestClient(t, srv).ListIssues(context.Background(), "achilles:x y")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || len(is) != 3 || is[2].Number != 3 || !is[0].HasLabel("Achilles") {
		t.Errorf("calls=%d issues=%+v", calls, is)
	}
}

func TestListIssues_DoesNotFollowForeignLink(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Link", `<https://evil.example/steal?page=2>; rel="next"`)
		io.WriteString(w, `[{"number":1,"state":"open"}]`)
	}))
	defer srv.Close()
	is, err := newTestClient(t, srv).ListIssues(context.Background(), "achilles")
	if err != nil || calls != 1 || len(is) != 1 {
		t.Errorf("calls=%d issues=%v err=%v", calls, is, err)
	}
}

func TestListIssues_TooManyPages(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+srv.URL+`/repos/acme/app/issues?page=n>; rel="next"`)
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	if _, err := newTestClient(t, srv).ListIssues(context.Background(), "achilles"); err == nil {
		t.Error("an unbounded listing must error, not loop or truncate silently")
	}
}

func TestRateLimit_RetryAfterHonored(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n <= 2 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, `{"number":5}`)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	var slept []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	num, err := c.CreateIssue(context.Background(), "t", "b", nil)
	if err != nil || num != 5 || n != 3 {
		t.Fatalf("num=%d n=%d err=%v", num, n, err)
	}
	if len(slept) != 2 || slept[0] != 7*time.Second || slept[1] != 7*time.Second {
		t.Errorf("slept=%v", slept)
	}
}

func TestRateLimit_SecondaryForbiddenUsesResetHeader(t *testing.T) {
	n := 0
	now := time.Unix(1_000_000, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1000020")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"message":"API rate limit exceeded"}`)
			return
		}
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	c.Now = func() time.Time { return now }
	var slept []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	if _, err := c.ListIssues(context.Background(), "achilles"); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 1 || slept[0] != 21*time.Second {
		t.Errorf("slept=%v", slept)
	}
}

func TestRateLimit_GivesUp(t *testing.T) {
	cases := []struct {
		name      string
		retryAft  string
		wantCalls int
	}{
		{"wait exceeds total budget", "90", 1},
		{"retries exhausted", "1", 4}, // 1 try + 3 retries
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n++
				w.Header().Set("Retry-After", tc.retryAft)
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer srv.Close()
			c := newTestClient(t, srv)
			c.Sleep = func(context.Context, time.Duration) error { return nil }
			err := c.AddComment(context.Background(), 1, "x")
			var ae *APIError
			if !errors.As(err, &ae) || ae.Status != 429 || n != tc.wantCalls {
				t.Errorf("err=%v calls=%d want %d", err, n, tc.wantCalls)
			}
		})
	}
}

func TestPlain403IsNotRetried(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	c.Sleep = func(context.Context, time.Duration) error { t.Error("must not sleep"); return nil }
	if err := c.AddComment(context.Background(), 1, "x"); err == nil || n != 1 {
		t.Errorf("err=%v calls=%d", err, n)
	}
}

func TestEnsureLabel(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"created", 201, `{"name":"achilles"}`, false},
		{"already exists", 422, `{"message":"Validation Failed","errors":[{"resource":"Label","code":"already_exists","field":"name"}]}`, false},
		{"other 422", 422, `{"message":"Validation Failed","errors":[{"code":"invalid"}]}`, true},
		{"forbidden", 403, `{"message":"nope"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/repos/acme/app/labels" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				b, _ := io.ReadAll(r.Body)
				json.Unmarshal(b, &got)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			err := newTestClient(t, srv).EnsureLabel(context.Background(), "achilles", "d73a4a", "managed")
			if (err != nil) != tc.wantErr {
				t.Errorf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if got["name"] != "achilles" || got["color"] != "d73a4a" {
				t.Errorf("payload=%v", got)
			}
		})
	}
}

func TestUpdateIssue_OnlySetFields(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" || r.URL.Path != "/repos/acme/app/issues/4" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		got = nil
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	body, labels := "new", []string{"achilles"}
	if err := c.UpdateIssue(context.Background(), 4, IssueUpdate{Body: &body, Labels: &labels}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["body"] != "new" {
		t.Errorf("payload=%v", got)
	}
	if err := c.ReopenIssue(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
	if got["state"] != "open" || got["state_reason"] != "reopened" || len(got) != 2 {
		t.Errorf("reopen payload=%v", got)
	}
}

func TestGetRepoAndVisibility(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"full_name":"acme/app","private":true}`, true},
		{`{"full_name":"acme/app","private":false,"visibility":"public"}`, false},
		{`{"full_name":"acme/app","private":false,"visibility":"internal"}`, true},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/repos/acme/app" {
				t.Errorf("path=%s", r.URL.Path)
			}
			io.WriteString(w, tc.body)
		}))
		got, err := newTestClient(t, srv).RepoIsPrivate(context.Background())
		srv.Close()
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v err=%v", tc.body, got, err)
		}
	}
}

func TestCreatePause_SkipsFirstCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"number":1}`) }))
	defer srv.Close()
	c := newTestClient(t, srv)
	c.CreatePause = time.Second
	var slept []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	ctx := context.Background()
	c.CreateIssue(ctx, "a", "b", nil)
	c.CreateIssue(ctx, "a", "b", nil)
	c.AddComment(ctx, 1, "x")
	if len(slept) != 2 || slept[0] != time.Second {
		t.Errorf("slept=%v", slept)
	}
}

package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New("tok", "acme/app", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
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

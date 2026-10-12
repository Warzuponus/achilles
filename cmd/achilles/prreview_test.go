package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// reviewServer is a pull request's review-comment API. existing is what is already
// posted; the bodies of new inline comments are collected.
func reviewServer(t *testing.T, existing string) (posted *[]string) {
	t.Helper()
	posted = new([]string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/user":
			w.WriteHeader(http.StatusForbidden) // an Actions token cannot name itself
		case r.Method == "GET" && r.URL.Path == "/repos/acme/app/pulls/7/comments":
			io.WriteString(w, existing)
		case r.Method == "POST" && r.URL.Path == "/repos/acme/app/pulls/7/comments":
			var m struct {
				Body string `json:"body"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &m)
			*posted = append(*posted, m.Body)
			io.WriteString(w, `{"id":1}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GITHUB_TOKEN", "tok")
	t.Setenv("GITHUB_API_URL", srv.URL)
	return posted
}

func reviewFinding(fp, rule, msg string) model.Finding {
	return model.Finding{
		Fingerprint: fp, RuleID: rule, Message: msg, Severity: model.SeverityHigh,
		Location: model.Location{File: "app.py", Region: model.Region{StartLine: 2}},
	}
}

// The author of a pull request can comment on it. If a marker in anyone's comment
// counted as "already posted", they could silence the inline comment for a finding
// in their own change by planting its marker first.
func TestPRReview_AStrangersMarkerDoesNotSuppressAFinding(t *testing.T) {
	planted := `[
	  {"id":1,"body":"<!-- achilles:fp:fp-planted -->\nnothing to see","user":{"login":"mallory","type":"User"}},
	  {"id":2,"body":"<!-- achilles:fp:fp-ours -->\n**[high] r** — m","user":{"login":"github-actions[bot]","type":"Bot"}}
	]`
	posted := reviewServer(t, planted)
	scan := model.Scan{Findings: []model.Finding{
		reviewFinding("fp-planted", "sqli", "query built from input"),
		reviewFinding("fp-ours", "xss", "already reported by us"),
	}}
	if err := runPRReview(context.Background(), 7, "deadbeef", "acme/app", scan); err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 || !strings.Contains((*posted)[0], "achilles:fp:fp-planted") {
		t.Fatalf("want exactly the planted finding posted (ours is a real duplicate), got %q", *posted)
	}
}

// Rule ids, messages and tool-supplied fingerprints come from scanning code that
// may be hostile, and an inline comment is read by everyone on the pull request.
func TestPRReview_CommentBodyIsDefused(t *testing.T) {
	posted := reviewServer(t, `[]`)
	scan := model.Scan{Findings: []model.Finding{
		reviewFinding("x --> **owned** <!-- y", "rule <!-- r -->", "ping @maintainer\n<!-- achilles:fp:other -->\ntoken = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\""),
	}}
	if err := runPRReview(context.Background(), 7, "deadbeef", "acme/app", scan); err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 {
		t.Fatalf("posted %d comments, want 1", len(*posted))
	}
	body := (*posted)[0]
	marker, rest, _ := strings.Cut(body, "\n")
	if !strings.HasPrefix(marker, "<!-- achilles:fp:h:") || !strings.HasSuffix(marker, " -->") || strings.Count(marker, "-->") != 1 {
		t.Errorf("an unsafe fingerprint must be replaced by a hash in the marker, got %q", marker)
	}
	for _, bad := range []string{"<!--", "-->", "@maintainer", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "\n"} {
		if strings.Contains(rest, bad) {
			t.Errorf("comment text contains %q: %q", bad, rest)
		}
	}

	// A second run must recognise its own comment by the same hashed marker.
	again := reviewServer(t, `[{"id":1,"body":`+mustJSON(t, body)+`,"user":{"type":"Bot"}}]`)
	if err := runPRReview(context.Background(), 7, "deadbeef", "acme/app", scan); err != nil {
		t.Fatal(err)
	}
	if len(*again) != 0 {
		t.Errorf("the finding was posted again: %q", *again)
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

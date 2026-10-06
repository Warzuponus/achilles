package issues_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/github"
	"github.com/Warzuponus/achilles/internal/issues"
	"github.com/Warzuponus/achilles/internal/model"
)

// TestSync_WithRealClientOverPaginatedAPI runs Sync through the real GitHub client
// against a fake server whose issue listing spans two pages: an issue on page 2
// must still be seen (and so not re-filed).
func TestSync_WithRealClientOverPaginatedAPI(t *testing.T) {
	f := model.Finding{Tool: "semgrep", RuleID: "sqli", Severity: model.SeverityHigh, Message: "m",
		Location: model.Location{File: "a.go", Region: model.Region{StartLine: 1}}, Fingerprint: "feedfacefeedface"}
	var creates, labelPosts int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/app":
			io.WriteString(w, `{"private":true}`)
		case r.Method == "GET" && r.URL.Path == "/repos/acme/app/issues":
			if r.URL.Query().Get("page") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s/repos/acme/app/issues?page=2>; rel="next"`, srv.URL))
				io.WriteString(w, `[{"number":1,"state":"open","body":"unrelated"}]`)
				return
			}
			b, _ := json.Marshal([]github.Issue{{Number: 2, State: "closed", Body: "<!-- achilles:fp:feedfacefeedface -->"}})
			w.Write(b)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/labels"):
			labelPosts++
			w.WriteHeader(201)
			io.WriteString(w, `{}`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/issues"):
			creates++
			io.WriteString(w, `{"number":9}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c, err := github.New("tok", "acme/app", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP, c.CreatePause = srv.Client(), 0
	g := model.Finding{Tool: "semgrep", RuleID: "xss", Severity: model.SeverityHigh, Message: "m",
		Location: model.Location{File: "b.go", Region: model.Region{StartLine: 2}}, Fingerprint: "0000111122223333"}
	sum, err := issues.Sync(context.Background(), c, model.Scan{Findings: []model.Finding{f, g}}, issues.Options{Repo: "acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	// f's issue is closed by a human on page 2 -> suppressed; only g is created.
	if creates != 1 || sum.Created != 1 || labelPosts != 1 {
		t.Errorf("creates=%d labels=%d summary=%+v", creates, labelPosts, sum)
	}
}

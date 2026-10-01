// Package github is a minimal GitHub REST client for Achilles's outward-facing
// PR/issue integrations (Tier C). It is deliberately small and interface-free at
// this layer: the caller supplies a token + repo (as GitHub Actions provides via
// GITHUB_TOKEN / GITHUB_REPOSITORY), and every method performs one documented
// REST call. Nothing here posts unless a command explicitly invokes it.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client talks to one repository's GitHub REST API.
type Client struct {
	Token   string
	BaseURL string // e.g. https://api.github.com (or a GHE URL)
	Owner   string
	Repo    string
	HTTP    *http.Client
}

// New builds a client. repo is "owner/name"; baseURL defaults to the public API.
func New(token, repo, baseURL string) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("no GitHub token (set GITHUB_TOKEN)")
	}
	o, r, ok := strings.Cut(repo, "/")
	if !ok || o == "" || r == "" {
		return nil, fmt.Errorf("repo must be owner/name, got %q", repo)
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &Client{Token: token, BaseURL: strings.TrimRight(baseURL, "/"), Owner: o, Repo: r, HTTP: http.DefaultClient}, nil
}

// markerFor returns the hidden HTML marker that identifies a Achilles comment of
// a given kind, so we update our own comment instead of posting a new one each run.
func markerFor(key string) string { return fmt.Sprintf("<!-- achilles:%s -->", key) }

// Comment is a GitHub issue/PR comment (the fields Achilles reads).
type Comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

// UpsertComment posts (or updates) a single "sticky" comment on an issue/PR: it
// finds a prior Achilles comment for key via its hidden marker and PATCHes it,
// else POSTs a new one. Returns whether it created (vs updated).
func (c *Client) UpsertComment(ctx context.Context, issue int, key, body string) (created bool, err error) {
	marker := markerFor(key)
	full := marker + "\n" + body

	id, err := c.findComment(ctx, issue, marker)
	if err != nil {
		return false, err
	}
	payload, _ := json.Marshal(map[string]string{"body": full})
	if id != 0 {
		return false, c.do(ctx, http.MethodPatch,
			fmt.Sprintf("/repos/%s/%s/issues/comments/%d", c.Owner, c.Repo, id), payload, nil)
	}
	return true, c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues/%d/comments", c.Owner, c.Repo, issue), payload, nil)
}

// findComment returns the id of the first comment containing marker, or 0.
func (c *Client) findComment(ctx context.Context, issue int, marker string) (int64, error) {
	var comments []Comment
	err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100", c.Owner, c.Repo, issue), nil, &comments)
	if err != nil {
		return 0, err
	}
	for _, cm := range comments {
		if strings.Contains(cm.Body, marker) {
			return cm.ID, nil
		}
	}
	return 0, nil
}

// ListPullComments returns a PR's existing review (inline) comments — used to
// dedupe so re-runs don't repost the same inline finding.
func (c *Client) ListPullComments(ctx context.Context, pr int) ([]Comment, error) {
	var out []Comment
	err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/pulls/%d/comments?per_page=100", c.Owner, c.Repo, pr), nil, &out)
	return out, err
}

// CreateReviewComment posts one inline comment on a PR's diff at path:line (on the
// added/RIGHT side), anchored to commitSHA (the PR head). GitHub rejects a comment
// on a line that isn't part of the diff (HTTP 422) — the caller treats that as a
// skip, not a hard error.
func (c *Client) CreateReviewComment(ctx context.Context, pr int, commitSHA, path string, line int, body string) error {
	payload, _ := json.Marshal(map[string]any{
		"body":      body,
		"commit_id": commitSHA,
		"path":      path,
		"line":      line,
		"side":      "RIGHT",
	})
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/pulls/%d/comments", c.Owner, c.Repo, pr), payload, nil)
}

// Issue is a GitHub issue (the fields Achilles reads). The pull_request field is
// non-nil when the "issue" is actually a PR — the /issues endpoint returns both —
// so callers skip those.
type Issue struct {
	Number      int              `json:"number"`
	Title       string           `json:"title"`
	Body        string           `json:"body"`
	State       string           `json:"state"`
	PullRequest *json.RawMessage `json:"pull_request,omitempty"`
}

// ListIssues returns all issues carrying the given label (open and closed), so the
// caller can dedupe against already-filed findings and reconcile resolved ones.
// PRs (which the endpoint also returns) are filtered out.
func (c *Client) ListIssues(ctx context.Context, label string) ([]Issue, error) {
	var raw []Issue
	err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/issues?state=all&labels=%s&per_page=100", c.Owner, c.Repo, label), nil, &raw)
	if err != nil {
		return nil, err
	}
	out := raw[:0]
	for _, is := range raw {
		if is.PullRequest == nil {
			out = append(out, is)
		}
	}
	return out, nil
}

// CreateIssue opens a new issue and returns its number.
func (c *Client) CreateIssue(ctx context.Context, title, body string, labels []string) (int, error) {
	payload, _ := json.Marshal(map[string]any{"title": title, "body": body, "labels": labels})
	var out Issue
	if err := c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues", c.Owner, c.Repo), payload, &out); err != nil {
		return 0, err
	}
	return out.Number, nil
}

// CloseIssue posts an optional comment then closes the issue. Used to reconcile a
// finding that is no longer detected (state_reason "completed").
func (c *Client) CloseIssue(ctx context.Context, number int, comment string) error {
	if comment != "" {
		payload, _ := json.Marshal(map[string]string{"body": comment})
		if err := c.do(ctx, http.MethodPost,
			fmt.Sprintf("/repos/%s/%s/issues/%d/comments", c.Owner, c.Repo, number), payload, nil); err != nil {
			return err
		}
	}
	payload, _ := json.Marshal(map[string]string{"state": "closed", "state_reason": "completed"})
	return c.do(ctx, http.MethodPatch,
		fmt.Sprintf("/repos/%s/%s/issues/%d", c.Owner, c.Repo, number), payload, nil)
}

// Pull is a pull request (the fields Achilles reads).
type Pull struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Head   struct {
		Ref string `json:"ref"`
	} `json:"head"`
	HTMLURL string `json:"html_url"`
}

// ListPullsForHead returns open PRs whose head branch is headRef (owner-scoped),
// so the caller can avoid re-opening an auto-fix PR that already exists.
func (c *Client) ListPullsForHead(ctx context.Context, headRef string) ([]Pull, error) {
	var out []Pull
	err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/pulls?state=open&head=%s:%s", c.Owner, c.Repo, c.Owner, headRef), nil, &out)
	return out, err
}

// CreatePull opens a pull request from head into base and returns it. Achilles
// only ever opens — it never merges (DESIGN §1 Non-Goals; auto-fix guardrail).
func (c *Client) CreatePull(ctx context.Context, title, head, base, body string) (Pull, error) {
	payload, _ := json.Marshal(map[string]any{"title": title, "head": head, "base": base, "body": body})
	var out Pull
	err := c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/pulls", c.Owner, c.Repo), payload, &out)
	return out, err
}

// do performs one REST call, decoding a JSON response into out (if non-nil).
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("github %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("github %s %s: decode: %w", method, path, err)
		}
	}
	return nil
}

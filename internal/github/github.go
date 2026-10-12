// Package github is a minimal GitHub REST client for Achilles's outward-facing
// PR/issue integrations. It is deliberately small and interface-free at
// this layer: the caller supplies a token + repo (as GitHub Actions provides via
// GITHUB_TOKEN / GITHUB_REPOSITORY), and every method performs one documented
// REST call. Nothing here posts unless a command explicitly invokes it.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bounds on rate-limit handling and pacing. Retrying forever would hang CI, so a
// call gives up after maxRetries attempts or once the waits it needs would
// exceed maxTotalWait in total.
const (
	maxRetries   = 3
	maxTotalWait = 60 * time.Second
	// defaultCreatePause spaces content-creating calls (new issues, comments):
	// GitHub's guidance is at least a second between them, or the secondary rate
	// limiter trips.
	defaultCreatePause = time.Second
	// maxPages bounds a paginated listing (100 items per page).
	maxPages = 50
)

// Client talks to one repository's GitHub REST API.
type Client struct {
	Token   string
	BaseURL string // e.g. https://api.github.com (or a GHE URL)
	Owner   string
	Repo    string
	HTTP    *http.Client

	// CreatePause is the delay inserted between content-creating calls
	// (CreateIssue, AddComment); the first call is not delayed. New sets it to one
	// second; tests set it to 0.
	CreatePause time.Duration
	// Sleep waits for d or until ctx is done. nil uses a real timer. Injectable so
	// tests never actually wait.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now returns the current time (used to turn X-RateLimit-Reset into a wait).
	// nil uses time.Now.
	Now func() time.Time

	created bool // a content-creating call has already been made (pacing)
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
	return &Client{Token: token, BaseURL: strings.TrimRight(baseURL, "/"), Owner: o, Repo: r, HTTP: http.DefaultClient, CreatePause: defaultCreatePause}, nil
}

// markerFor returns the hidden HTML marker that identifies a Achilles comment of
// a given kind, so we update our own comment instead of posting a new one each run.
func markerFor(key string) string { return fmt.Sprintf("<!-- achilles:%s -->", key) }

// Comment is a GitHub issue/PR comment (the fields Achilles reads).
type Comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
		Type  string `json:"type"` // "User", "Bot", ...
	} `json:"user"`
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

// findComment returns the id of Achilles' own earlier comment for marker, or 0.
//
// Anyone who can comment on a pull request can write the marker, and a token with
// write access can edit anyone's comment. Matching the marker anywhere in any
// comment therefore let a stranger have their comment "adopted": Achilles kept
// writing its summary into a comment the stranger owns and can rewrite between
// runs. So a comment counts only if it starts with the marker AND was written by
// the identity this token acts as (or, when the token cannot name itself, as an
// Actions token cannot, by a bot account).
func (c *Client) findComment(ctx context.Context, issue int, marker string) (int64, error) {
	var candidates []Comment
	for page := 1; ; page++ {
		if page > maxPages {
			return 0, fmt.Errorf("github: more than %d pages of comments on #%d; refusing to guess which one is ours", maxPages, issue)
		}
		var comments []Comment
		err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100&page=%d", c.Owner, c.Repo, issue, page), nil, &comments)
		if err != nil {
			return 0, err
		}
		for _, cm := range comments {
			if strings.HasPrefix(strings.TrimLeft(cm.Body, " \t\r\n"), marker) {
				candidates = append(candidates, cm)
			}
		}
		if len(comments) < 100 {
			break
		}
	}
	if len(candidates) == 0 {
		return 0, nil
	}
	if own := c.Own(ctx, candidates); len(own) > 0 {
		return own[0].ID, nil
	}
	return 0, nil
}

// Own returns the comments written by the identity this token acts as. When the
// token cannot name itself (an Actions or GitHub App installation token), comments
// by bot accounts are taken to be ours: an ordinary user cannot post as a bot.
// It makes no API call when comments is empty.
func (c *Client) Own(ctx context.Context, comments []Comment) []Comment {
	if len(comments) == 0 {
		return nil
	}
	login := c.identity(ctx)
	var own []Comment
	for _, cm := range comments {
		if (login != "" && strings.EqualFold(cm.User.Login, login)) || (login == "" && cm.User.Type == "Bot") {
			own = append(own, cm)
		}
	}
	return own
}

// identity returns the login this token acts as, or "" when the API will not say:
// GET /user is refused for the installation tokens GitHub Actions and GitHub Apps
// use. Callers must treat "" as "unknown", never as a match.
func (c *Client) identity(ctx context.Context) string {
	var u struct {
		Login string `json:"login"`
	}
	if err := c.do(ctx, http.MethodGet, "/user", nil, &u); err != nil {
		return ""
	}
	return u.Login
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

// Label is a label attached to an issue.
type Label struct {
	Name string `json:"name"`
}

// Issue is a GitHub issue (the fields Achilles reads). The pull_request field is
// non-nil when the "issue" is actually a PR — the /issues endpoint returns both —
// so callers skip those.
type Issue struct {
	Number      int              `json:"number"`
	Title       string           `json:"title"`
	Body        string           `json:"body"`
	State       string           `json:"state"`
	StateReason string           `json:"state_reason,omitempty"`
	Labels      []Label          `json:"labels,omitempty"`
	PullRequest *json.RawMessage `json:"pull_request,omitempty"`
}

// HasLabel reports whether the issue carries the named label (case-insensitive,
// as GitHub treats label names).
func (is Issue) HasLabel(name string) bool {
	for _, l := range is.Labels {
		if strings.EqualFold(l.Name, name) {
			return true
		}
	}
	return false
}

// ListIssues returns all issues carrying the given label (open and closed), so the
// caller can dedupe against already-filed findings and reconcile resolved ones.
// It follows pagination (Link rel="next"); a listing longer than maxPages pages is
// an error rather than a silent truncation, since a partial view would make the
// caller re-file issues it cannot see. PRs (which the endpoint also returns) are
// filtered out.
func (c *Client) ListIssues(ctx context.Context, label string) ([]Issue, error) {
	next := fmt.Sprintf("%s/repos/%s/%s/issues?state=all&labels=%s&per_page=100",
		c.BaseURL, c.Owner, c.Repo, url.QueryEscape(label))
	var out []Issue
	for page := 0; next != ""; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("github: more than %d pages of issues for label %q; refusing to act on a partial listing", maxPages, label)
		}
		var raw []Issue
		hdr, err := c.doURL(ctx, http.MethodGet, next, nil, &raw)
		if err != nil {
			return nil, err
		}
		for _, is := range raw {
			if is.PullRequest == nil {
				out = append(out, is)
			}
		}
		next = c.nextLink(hdr.Get("Link"))
	}
	return out, nil
}

var linkNextRE = regexp.MustCompile(`<([^>]+)>\s*;[^,]*\brel="?next"?`)

// nextLink extracts the rel="next" URL from a Link header. It returns "" when
// there is none, or when the URL points at a different origin than BaseURL — the
// bearer token must never be sent to a host the caller did not configure.
func (c *Client) nextLink(link string) string {
	m := linkNextRE.FindStringSubmatch(link)
	if m == nil {
		return ""
	}
	nu, err := url.Parse(m[1])
	if err != nil {
		return ""
	}
	bu, err := url.Parse(c.BaseURL)
	if err != nil || nu.Scheme != bu.Scheme || nu.Host != bu.Host {
		return ""
	}
	return nu.String()
}

// CreateIssue opens a new issue and returns its number. Creations are paced by
// CreatePause to stay under GitHub's secondary rate limit.
func (c *Client) CreateIssue(ctx context.Context, title, body string, labels []string) (int, error) {
	if err := c.pace(ctx); err != nil {
		return 0, err
	}
	payload, _ := json.Marshal(map[string]any{"title": title, "body": body, "labels": labels})
	var out Issue
	if err := c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues", c.Owner, c.Repo), payload, &out); err != nil {
		return 0, err
	}
	return out.Number, nil
}

// IssueUpdate is a partial update of an issue; nil fields are left unchanged.
// Labels, when non-nil, REPLACES the issue's whole label set.
type IssueUpdate struct {
	Title       *string
	Body        *string
	State       *string // "open" | "closed"
	StateReason *string // "completed" | "not_planned" | "reopened"
	Labels      *[]string
}

// UpdateIssue PATCHes the fields set in u.
func (c *Client) UpdateIssue(ctx context.Context, number int, u IssueUpdate) error {
	m := map[string]any{}
	if u.Title != nil {
		m["title"] = *u.Title
	}
	if u.Body != nil {
		m["body"] = *u.Body
	}
	if u.State != nil {
		m["state"] = *u.State
	}
	if u.StateReason != nil {
		m["state_reason"] = *u.StateReason
	}
	if u.Labels != nil {
		m["labels"] = *u.Labels
	}
	payload, _ := json.Marshal(m)
	return c.do(ctx, http.MethodPatch,
		fmt.Sprintf("/repos/%s/%s/issues/%d", c.Owner, c.Repo, number), payload, nil)
}

// ReopenIssue sets an issue's state back to open.
func (c *Client) ReopenIssue(ctx context.Context, number int) error {
	open, reopened := "open", "reopened"
	return c.UpdateIssue(ctx, number, IssueUpdate{State: &open, StateReason: &reopened})
}

// AddComment posts a comment on an issue or PR. Paced like CreateIssue.
func (c *Client) AddComment(ctx context.Context, number int, body string) error {
	if err := c.pace(ctx); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues/%d/comments", c.Owner, c.Repo, number), payload, nil)
}

// Repo is the subset of a repository the issue workflow needs.
type Repo struct {
	FullName   string `json:"full_name"`
	Private    bool   `json:"private"`
	Visibility string `json:"visibility"`
}

// GetRepo fetches the repository's metadata.
func (c *Client) GetRepo(ctx context.Context) (Repo, error) {
	var out Repo
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s", c.Owner, c.Repo), nil, &out)
	return out, err
}

// RepoIsPrivate reports whether the repository is private or internal (i.e. not
// world-readable). GitHub reports both as private=true.
func (c *Client) RepoIsPrivate(ctx context.Context) (bool, error) {
	r, err := c.GetRepo(ctx)
	if err != nil {
		return false, err
	}
	return r.Private || r.Visibility == "private" || r.Visibility == "internal", nil
}

// EnsureLabel creates the label if it does not exist yet. A 422 "already_exists"
// response is success, so it is safe to call on every run.
func (c *Client) EnsureLabel(ctx context.Context, name, color, description string) error {
	payload, _ := json.Marshal(map[string]string{"name": name, "color": color, "description": description})
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/labels", c.Owner, c.Repo), payload, nil)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusUnprocessableEntity && strings.Contains(ae.Body, "already_exists") {
		return nil
	}
	return err
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

// APIError is a non-2xx GitHub response.
type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("github %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// pace waits CreatePause before every content-creating call but the first.
func (c *Client) pace(ctx context.Context) error {
	if c.created && c.CreatePause > 0 {
		if err := c.sleep(ctx, c.CreatePause); err != nil {
			return err
		}
	}
	c.created = true
	return nil
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// do performs one REST call, decoding a JSON response into out (if non-nil).
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	_, err := c.doURL(ctx, method, c.BaseURL+path, body, out)
	return err
}

// doURL performs one REST call against a full URL and returns the response
// headers (for pagination). Rate-limited responses (429, or 403 that GitHub marks
// as a rate limit) are retried up to maxRetries times, honoring Retry-After /
// X-RateLimit-Reset, and give up if the waits would exceed maxTotalWait.
func (c *Client) doURL(ctx context.Context, method, fullURL string, body []byte, out any) (http.Header, error) {
	label := strings.TrimPrefix(fullURL, c.BaseURL)
	var waited time.Duration
	for attempt := 0; ; attempt++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github %s %s: %w", method, label, err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil {
				if err := json.Unmarshal(data, out); err != nil {
					return nil, fmt.Errorf("github %s %s: decode: %w", method, label, err)
				}
			}
			return resp.Header, nil
		}
		apiErr := &APIError{Method: method, Path: label, Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
		if wait, ok := c.rateLimitWait(resp, apiErr.Body, attempt); ok && attempt < maxRetries && waited+wait <= maxTotalWait {
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			waited += wait
			continue
		}
		return nil, apiErr
	}
}

// rateLimitWait reports whether resp is a rate-limit response and how long to
// wait before retrying. Retry-After wins, then X-RateLimit-Reset; with neither
// (a bare secondary limit) it backs off 10s, 20s, 40s.
func (c *Client) rateLimitWait(resp *http.Response, body string, attempt int) (time.Duration, bool) {
	h := resp.Header
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
	case http.StatusForbidden:
		limited := h.Get("Retry-After") != "" || h.Get("X-RateLimit-Remaining") == "0" ||
			strings.Contains(strings.ToLower(body), "rate limit")
		if !limited {
			return 0, false // a real permission error: retrying cannot help
		}
	default:
		return 0, false
	}
	if ra := h.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	if reset := h.Get("X-RateLimit-Reset"); reset != "" && h.Get("X-RateLimit-Remaining") == "0" {
		if epoch, err := strconv.ParseInt(strings.TrimSpace(reset), 10, 64); err == nil {
			if d := time.Unix(epoch, 0).Sub(c.now()); d > 0 {
				return d + time.Second, true
			}
			return time.Second, true
		}
	}
	return time.Duration(10<<attempt) * time.Second, true
}

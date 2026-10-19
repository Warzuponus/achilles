// Package gitlab is a minimal GitLab REST client for Achilles' merge request
// summary note. Like internal/github it is deliberately small: the caller supplies
// a token, the project and the API URL (GitLab CI provides the last two as
// CI_PROJECT_ID and CI_API_V4_URL), and every method performs one documented REST
// call. Nothing here posts unless a command explicitly invokes it.
package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is gitlab.com's API, used outside GitLab CI.
	DefaultBaseURL = "https://gitlab.com/api/v4"

	maxRetries   = 3
	maxTotalWait = 60 * time.Second
	// maxPages bounds a paginated listing (100 items per page).
	maxPages = 50
	// MaxNoteBytes keeps a note under GitLab's limit of 1,000,000 characters for a
	// note body, with room for the marker and the truncation notice.
	MaxNoteBytes = 900_000
)

// Client talks to one project's GitLab REST API.
type Client struct {
	Token   string
	BaseURL string // e.g. https://gitlab.com/api/v4 or $CI_API_V4_URL
	Project string // numeric id or "group/project"
	HTTP    *http.Client

	// Sleep waits for d or until ctx is done. nil uses a real timer. Injectable so
	// tests never actually wait.
	Sleep func(ctx context.Context, d time.Duration) error
}

// New builds a client. The base URL must be https, except for a loopback host
// (a local test server): the token travels in a header on every call.
func New(token, project, baseURL string) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("no GitLab token (set ACHILLES_GITLAB_TOKEN to a token with the api scope; CI_JOB_TOKEN cannot write notes)")
	}
	if strings.TrimSpace(project) == "" {
		return nil, fmt.Errorf("no GitLab project (set --gitlab-project, or run in GitLab CI where CI_PROJECT_ID is set)")
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("gitlab: bad API URL %q", baseURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("gitlab: API URL %q is not https; refusing to send the token over it", baseURL)
	}
	return &Client{Token: token, BaseURL: strings.TrimRight(baseURL, "/"), Project: strings.TrimSpace(project), HTTP: http.DefaultClient}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// markerFor returns the hidden HTML marker that identifies an Achilles note of a
// given kind, so a re-run updates its note instead of posting another.
func markerFor(key string) string { return fmt.Sprintf("<!-- achilles:%s -->", key) }

// Note is a GitLab merge request note (the fields Achilles reads).
type Note struct {
	ID     int64  `json:"id"`
	Body   string `json:"body"`
	System bool   `json:"system"`
	Author struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"author"`
}

// UpsertMergeRequestNote posts (or updates) a single "sticky" note on a merge
// request: it finds Achilles' earlier note for key and PUTs the new body into it,
// else POSTs a new note. Returns whether it created (vs updated).
func (c *Client) UpsertMergeRequestNote(ctx context.Context, mr int, key, body string) (created bool, err error) {
	if mr <= 0 {
		return false, fmt.Errorf("gitlab: merge request IID must be positive, got %d", mr)
	}
	marker := markerFor(key)
	full := marker + "\n" + truncate(body)

	id, err := c.findNote(ctx, mr, marker)
	if err != nil {
		return false, err
	}
	payload, _ := json.Marshal(map[string]string{"body": full})
	base := fmt.Sprintf("/projects/%s/merge_requests/%d/notes", url.PathEscape(c.Project), mr)
	if id != 0 {
		return false, c.do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", base, id), payload, nil)
	}
	return true, c.do(ctx, http.MethodPost, base, payload, nil)
}

// findNote returns the id of Achilles' own earlier note for marker, or 0.
//
// Anyone who can comment on the merge request can write the marker, so a note
// counts only if it starts with the marker AND was written by the user this token
// acts as. GitLab tokens (personal, project and group access tokens) can always
// name their user, so an unknown identity is an error, never a guess.
func (c *Client) findNote(ctx context.Context, mr int, marker string) (int64, error) {
	me, err := c.identity(ctx)
	if err != nil {
		return 0, err
	}
	for page := 1; ; page++ {
		if page > maxPages {
			return 0, fmt.Errorf("gitlab: more than %d pages of notes on !%d; refusing to guess which one is ours", maxPages, mr)
		}
		var notes []Note
		h, err := c.doURL(ctx, http.MethodGet, fmt.Sprintf("%s/projects/%s/merge_requests/%d/notes?per_page=100&page=%d&sort=asc&order_by=created_at",
			c.BaseURL, url.PathEscape(c.Project), mr, page), nil, &notes)
		if err != nil {
			return 0, err
		}
		for _, n := range notes {
			if !n.System && n.Author.ID == me && strings.HasPrefix(strings.TrimLeft(n.Body, " \t\r\n"), marker) {
				return n.ID, nil
			}
		}
		if next := strings.TrimSpace(h.Get("X-Next-Page")); next == "" || len(notes) < 100 {
			return 0, nil
		}
	}
}

// identity returns the id of the user this token acts as.
func (c *Client) identity(ctx context.Context) (int64, error) {
	var u struct {
		ID int64 `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, "/user", nil, &u); err != nil {
		return 0, fmt.Errorf("gitlab: cannot tell which user this token acts as (it needs the api or read_user scope): %w", err)
	}
	if u.ID == 0 {
		return 0, fmt.Errorf("gitlab: GET /user named no user")
	}
	return u.ID, nil
}

// truncate keeps a note body under MaxNoteBytes, cutting at a line boundary.
func truncate(body string) string {
	if len(body) <= MaxNoteBytes {
		return body
	}
	cut := body[:MaxNoteBytes]
	if i := strings.LastIndexByte(cut, '\n'); i > MaxNoteBytes/2 {
		cut = cut[:i]
	}
	return cut + "\n\n_The summary was cut to fit GitLab's note size limit; the full report is in the job's artifacts._\n"
}

// APIError is a non-2xx response.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gitlab %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
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

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	_, err := c.doURL(ctx, method, c.BaseURL+path, body, out)
	return err
}

// doURL performs one REST call against a full URL and returns the response
// headers (for pagination). 429 and 5xx responses are retried up to maxRetries
// times, honoring Retry-After, and give up once the waits would exceed
// maxTotalWait.
func (c *Client) doURL(ctx context.Context, method, fullURL string, body []byte, out any) (http.Header, error) {
	label := strings.TrimPrefix(fullURL, c.BaseURL)
	if i := strings.IndexByte(label, '?'); i >= 0 {
		label = label[:i]
	}
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
		req.Header.Set("PRIVATE-TOKEN", c.Token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("gitlab %s %s: %w", method, label, err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil {
				if err := json.Unmarshal(data, out); err != nil {
					return nil, fmt.Errorf("gitlab %s %s: decode: %w", method, label, err)
				}
			}
			return resp.Header, nil
		}
		msg := strings.TrimSpace(string(data))
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		apiErr := &APIError{Method: method, Path: label, Status: resp.StatusCode, Body: msg}
		if wait, ok := retryWait(method, resp, attempt); ok && attempt < maxRetries && waited+wait <= maxTotalWait {
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			waited += wait
			continue
		}
		return nil, apiErr
	}
}

// retryWait reports whether resp is worth retrying and how long to wait first:
// Retry-After when GitLab sends it, else 2s, 4s, 8s. A rate-limited call (429)
// was not carried out, so any call is retried; after a server error only the
// idempotent ones are, since a POST may have created its note before failing.
func retryWait(method string, resp *http.Response, attempt int) (time.Duration, bool) {
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
	case resp.StatusCode >= 500 && method != http.MethodPost:
	default:
		return 0, false
	}
	if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	return time.Duration(2<<attempt) * time.Second, true
}

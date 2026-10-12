package research

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Grounder says whether a cited advisory really exists.
//
// The research agent was called "citation-mandatory", but the check was that the
// citation field was not empty. A model that invents CVE-2023-12345 passes that.
// An issue is only as real as its source, and a rule synthesized from an invented
// advisory looks exactly like one synthesized from a real one. So the id a model
// cites is looked up.
type Grounder interface {
	// Resolve reports whether id names a published advisory. An error means the
	// lookup could not be done (not that the advisory is missing).
	Resolve(ctx context.Context, id string) (bool, error)
}

// advisoryID matches the identifiers a lookup can check.
var advisoryID = regexp.MustCompile(`(?i)\b(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|GO-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d{4}|OSV-\d{4}-\d+|MAL-\d{4}-\d+)\b`)

// AdvisoryIDs returns the advisory identifiers in a citation, normalized
// (upper-case, except that a GHSA id keeps its lower-case groups) and de-duplicated.
func AdvisoryIDs(citation string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range advisoryID.FindAllString(citation, -1) {
		id := strings.ToUpper(m)
		if strings.HasPrefix(id, "GHSA-") {
			id = "GHSA-" + strings.ToLower(id[5:])
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// HTTPGrounder resolves advisory ids against OSV (which indexes GHSA, Go, PyPI,
// RustSec and many CVE records) and, for a CVE id OSV does not have, against the
// CVE Program's own record service. Only the id is sent.
type HTTPGrounder struct {
	Client  *http.Client
	OSVBase string // default https://api.osv.dev
	CVEBase string // default https://cveawg.mitre.org
}

// NewHTTPGrounder returns a grounder using the public services.
func NewHTTPGrounder() *HTTPGrounder {
	return &HTTPGrounder{
		Client:  &http.Client{Timeout: 15 * time.Second},
		OSVBase: "https://api.osv.dev",
		CVEBase: "https://cveawg.mitre.org",
	}
}

// Hosts lists the hosts the grounder contacts, for telling the user.
func (g *HTTPGrounder) Hosts() []string {
	var hosts []string
	for _, b := range []string{g.OSVBase, g.CVEBase} {
		if u, err := url.Parse(b); err == nil && u.Host != "" {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

func (g *HTTPGrounder) Resolve(ctx context.Context, id string) (bool, error) {
	found, err := g.exists(ctx, strings.TrimRight(g.OSVBase, "/")+"/v1/vulns/"+url.PathEscape(id))
	if err != nil || found {
		return found, err
	}
	if strings.HasPrefix(id, "CVE-") {
		return g.exists(ctx, strings.TrimRight(g.CVEBase, "/")+"/api/cve/"+url.PathEscape(id))
	}
	return false, nil
}

// exists does one lookup: 200 is found, 404 is not found, anything else is an
// error, because "the service is having trouble" must not read as "no such advisory".
func (g *HTTPGrounder) exists(ctx context.Context, endpoint string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("advisory lookup: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("advisory lookup: %s answered HTTP %d", req.URL.Host, resp.StatusCode)
	}
}

// grounded reports whether a citation names at least one advisory that exists.
// A citation with no checkable id is not grounded: a URL alone can be made up as
// easily as an id, and cannot be checked without fetching whatever it points at.
func grounded(ctx context.Context, g Grounder, citation string) (bool, error) {
	for _, id := range AdvisoryIDs(citation) {
		ok, err := g.Resolve(ctx, id)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

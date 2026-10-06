// Package redact masks secret material before text leaves the machine or lands in
// a place others can read: the War Room, GitHub issue bodies, and LLM prompts.
// Findings frequently contain secrets (a leaked key is the finding), so every
// outward path goes through here.
//
// Two strengths exist because the right trade-off differs:
//
//   - Secrets is conservative-toward-hiding. It also masks any long standalone
//     token, which is right for an issue body or UI but would mangle a hash or
//     identifier in code an LLM needs to read.
//   - Prompt masks only well-formed credentials (known token prefixes, private key
//     blocks, secret-named assignments), so the model still sees the code's shape.
package redact

import "regexp"

// Mask replaces redacted material.
const Mask = "[REDACTED]"

var (
	privateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)
	// Credentials with a distinctive, well-known shape.
	knownTokens = regexp.MustCompile(`AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_\-]{20,}|xox[abprs]-[A-Za-z0-9\-]{10,}|sk-(?:or-v1-|ant-|proj-)?[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)
	// key/secret/token/password assignments: `secret = "..."`, `api_key: ...`.
	assignment = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)(["']?\s*[:=]\s*)("[^"\n]{6,}"|'[^'\n]{6,}'|[^\s"',;)]{6,})`)
	// Long standalone high-entropy hex/base64 tokens (>= 32 chars).
	longToken = regexp.MustCompile(`\b[A-Za-z0-9+/_\-]{32,}\b`)
)

// Prompt masks well-formed credentials only. Use it on code sent to an LLM.
func Prompt(s string) string {
	s = privateKey.ReplaceAllString(s, Mask)
	s = knownTokens.ReplaceAllString(s, Mask)
	return assignment.ReplaceAllString(s, "$1$2"+Mask)
}

// Secrets is Prompt plus a mask over any long standalone token. Use it on text
// that humans will read in a shared place (issue bodies, the War Room).
func Secrets(s string) string {
	return longToken.ReplaceAllString(Prompt(s), Mask)
}

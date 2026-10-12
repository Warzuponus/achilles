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
	// PEM private keys, and PGP private key blocks ("... PRIVATE KEY BLOCK-----").
	privateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)`)
	// Credentials with a distinctive, well-known shape.
	knownTokens = regexp.MustCompile(`AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_\-]{20,}|xox[abprs]-[A-Za-z0-9\-]{10,}|sk-(?:or-v1-|ant-|proj-)?[A-Za-z0-9_\-]{20,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_\-]{35}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)
	// Webhook URLs whose path is the credential (Slack, Discord).
	webhookURL = regexp.MustCompile(`(https://hooks\.slack\.com/(?:services|workflows|triggers)/|https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/)[A-Za-z0-9_\-/]{8,}`)
	// The password in a URL: scheme://user:PASSWORD@host. This is how database and
	// broker connection strings carry theirs.
	urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@"'<>]*:)[^\s/@"'<>]+(@)`)
	// A password position that holds a placeholder, not a password: %s, ${VAR},
	// $VAR, {name}, <password>, ***. Masking those would tell a reader (or a model
	// judging a "hardcoded credential" finding) that a real password is there.
	placeholder = regexp.MustCompile(`^(?:%[a-z]|\$\{?[A-Za-z_]|\{|<|\*+$|x{3,}$)`)
	// HTTP credentials: `Authorization: Basic ...`, `Authorization: Bearer ...`, and
	// a bare `Bearer <token>`. The token has no shape of its own, so the scheme
	// word is the signal.
	authHeader  = regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*["']?(?:basic|bearer|token|digest)\s+)[A-Za-z0-9._~+/=\-]{8,}`)
	bearerToken = regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/=\-]{20,}`)
	// key/secret/token/password assignments: `secret = "..."`, `api_key: ...`,
	// `secretKey = ...`, `SECRET_ACCESS_KEY=...`. The longer names come first so
	// "secret_key" is not read as "secret" followed by something that is not an
	// assignment.
	assignment = regexp.MustCompile(`(?i)(password|passwd|pwd|secret[_-]?(?:access[_-]?)?key|secret|auth[_-]?token|token|api[_-]?key|access[_-]?key|private[_-]?key)(["']?\s*[:=]\s*)("[^"\n]{6,}"|'[^'\n]{6,}'|[^\s"',;)]{6,})`)
	// Long standalone high-entropy hex/base64 tokens (>= 32 chars).
	longToken = regexp.MustCompile(`\b[A-Za-z0-9+/_\-]{32,}\b`)
)

// Prompt masks well-formed credentials only. Use it on code sent to an LLM.
func Prompt(s string) string {
	s = privateKey.ReplaceAllString(s, Mask)
	s = webhookURL.ReplaceAllString(s, "${1}"+Mask)
	s = urlUserinfo.ReplaceAllStringFunc(s, maskUserinfo)
	s = authHeader.ReplaceAllString(s, "${1}"+Mask)
	s = bearerToken.ReplaceAllString(s, "${1}"+Mask)
	s = knownTokens.ReplaceAllString(s, Mask)
	return assignment.ReplaceAllString(s, "$1$2"+Mask)
}

// Secrets is Prompt plus a mask over any long standalone token. Use it on text
// that humans will read in a shared place (issue bodies, the War Room).
func Secrets(s string) string {
	return longToken.ReplaceAllString(Prompt(s), Mask)
}

// maskUserinfo masks the password of one scheme://user:password@ match, unless the
// password position holds a placeholder.
func maskUserinfo(m string) string {
	sub := urlUserinfo.FindStringSubmatch(m)
	if sub == nil {
		return m
	}
	password := m[len(sub[1]) : len(m)-len(sub[2])]
	if placeholder.MatchString(password) {
		return m
	}
	return sub[1] + Mask + sub[2]
}

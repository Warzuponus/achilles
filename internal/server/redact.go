package server

import "regexp"

// Redaction masks secret material so it never reaches the UI, API, or reports
// (DESIGN.md §10: findings frequently *contain* secrets). Conservative by
// design: we mask obvious credentials rather than aggressively scrubbing code.

var redactors = []*regexp.Regexp{
	// AWS access key IDs.
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// key/secret/token/password assignments: `secret = "..."`, `api_key: ...`.
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key)(\s*[:=]\s*)("?[^\s"']{6,}"?)`),
	// Long standalone high-entropy hex/base64 tokens (>= 32 chars).
	regexp.MustCompile(`\b[A-Za-z0-9+/_\-]{32,}\b`),
}

const mask = "[REDACTED]"

// Redact returns s with secret-like substrings masked.
func Redact(s string) string {
	out := s
	// Preserve the key name for the assignment pattern; mask only the value.
	out = redactors[0].ReplaceAllString(out, mask)
	out = redactors[1].ReplaceAllString(out, "$1$2"+mask)
	out = redactors[2].ReplaceAllString(out, mask)
	return out
}

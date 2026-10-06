package server

import "github.com/Warzuponus/achilles/internal/redact"

// Redact masks secret-like substrings so they never reach the UI, API, or reports
// (DESIGN.md §10: findings frequently *contain* secrets). The patterns live in
// internal/redact so GitHub issue bodies and LLM prompts share them.
func Redact(s string) string { return redact.Secrets(s) }

const mask = redact.Mask

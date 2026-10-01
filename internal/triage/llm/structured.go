package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strings"
)

var reasoningBlock = regexp.MustCompile(`(?is)<(think|thinking|reasoning)>.*?</(think|thinking|reasoning)>`)

// stripReasoning removes chain-of-thought blocks that reasoning models inline in
// their content. They routinely contain braces (pseudo-JSON, code), which would
// otherwise poison the first-'{'..last-'}' extraction below.
func stripReasoning(s string) string {
	s = reasoningBlock.ReplaceAllString(s, "")
	// Some chat templates open the block in the prompt, so only a closing tag
	// appears in the output: keep what follows the last one.
	if i := strings.LastIndex(strings.ToLower(s), "</think>"); i >= 0 {
		s = s[i+len("</think>"):]
	}
	return s
}

// ExtractJSON returns the substring from the first '{' to the last '}', so a
// model that wraps JSON in prose or code fences still parses, after dropping any
// inline reasoning blocks. This is the last-resort net for endpoints without
// strict structured output.
func ExtractJSON(s string) string {
	s = stripReasoning(s)
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

// CompleteJSON requests json_schema output and, if the endpoint rejects the
// response_format, retries once with plain JSON mode (DESIGN.md §7 portability).
// Callers pass the response through ExtractJSON before unmarshalling.
//
// The fallback fires only when the failure could be about response_format. A bad
// credential, a rate limit, a timeout or a cancelled context would fail the same
// way a second time, so retrying them just doubles load on an unhappy endpoint.
func CompleteJSON(ctx context.Context, c Client, msgs []Message, schema *Schema) (Response, error) {
	resp, err := c.Complete(ctx, Request{Messages: msgs, Temperature: 0, Schema: schema})
	if err == nil || schema == nil || !formatRejected(ctx, err) {
		return resp, err
	}
	return c.Complete(ctx, Request{Messages: msgs, Temperature: 0, JSON: true})
}

// formatRejected reports whether err plausibly means "this server does not
// support the requested response_format".
func formatRejected(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var he *HTTPError
	if errors.As(err, &he) {
		switch he.Status {
		// 400/422: schema or field rejected. 404/405/415: route or media type
		// unsupported. 500/501: some runtimes crash compiling a schema grammar.
		case http.StatusBadRequest, http.StatusUnprocessableEntity,
			http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUnsupportedMediaType,
			http.StatusInternalServerError, http.StatusNotImplemented:
			return true
		}
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return false // connection refused, DNS, timeout
	}
	// A 200 whose body was unusable (decode failure, error object, no choices).
	return true
}

// CompleteAndDecode requests structured output, decodes it into out, and checks
// it with validate (if non-nil). If either the decode OR validate fails — open
// models fence their JSON, drift on nested shapes, or silently omit required
// fields (which json.Unmarshal tolerates), even when sent
// response_format=json_schema — it makes ONE repair round-trip, handing the model
// its own output plus the failure reason and the schema, asking for valid JSON
// only. It returns the Response whose content actually satisfied both (so callers
// record the right provenance). This keeps every structured agent tolerant of
// loose endpoints without per-agent retry code.
//
// validate lets a caller reject a decode that parsed but is unusable (e.g. an
// empty summary or a missing required field) — pass nil to skip.
func CompleteAndDecode(ctx context.Context, c Client, msgs []Message, schema *Schema, out any, validate func() error) (Response, error) {
	resp, err := CompleteJSON(ctx, c, msgs, schema)
	if err != nil {
		return resp, err
	}
	reason := decodeAndValidate(resp.Content, out, validate)
	if reason == nil {
		return resp, nil
	}

	def := ""
	if schema != nil {
		def = string(schema.Definition)
	}
	repair := make([]Message, len(msgs), len(msgs)+2)
	copy(repair, msgs)
	repair = append(repair,
		Message{Role: RoleAssistant, Content: resp.Content},
		Message{Role: RoleUser, Content: fmt.Sprintf(
			"That response was not acceptable (%v). Reply with ONLY a single JSON object — no "+
				"prose, no markdown fences — using exactly these field names and value types, and "+
				"filling every required field:\n%s", reason, def)})
	resp2, err2 := c.Complete(ctx, Request{Messages: repair, Temperature: 0, JSON: true})
	if err2 != nil {
		// Hand back the original reply, not the empty one: it was a real answer and
		// a caller with a lenient parser can still use it.
		return resp, fmt.Errorf("structured decode failed (%v); repair request errored: %w", reason, err2)
	}
	// Tokens were spent on both calls; report both.
	resp2.Usage.Add(resp.Usage)
	if reason2 := decodeAndValidate(resp2.Content, out, validate); reason2 != nil {
		return resp2, fmt.Errorf("structured output still unacceptable after repair: %w", reason2)
	}
	return resp2, nil
}

// decodeAndValidate unmarshals content into out (via ExtractJSON) and, on success,
// runs validate. It returns nil when both pass, else the reason to repair.
func decodeAndValidate(content string, out any, validate func() error) error {
	// A repair attempt decodes into the same value; clear it so fields set by a
	// failed first attempt cannot leak into the second.
	if rv := reflect.ValueOf(out); rv.Kind() == reflect.Ptr && !rv.IsNil() {
		rv.Elem().SetZero()
	}
	if err := json.Unmarshal([]byte(ExtractJSON(content)), out); err != nil {
		return err
	}
	if validate != nil {
		return validate()
	}
	return nil
}

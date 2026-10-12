package normalize

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/redact"
)

// ScrubRaw returns a scanner's raw output with the matched text of credential
// findings removed, for anything that is about to be stored or written out (the
// Evidence Vault's raw_output record, --sarif-out).
//
// A secret scanner's report is a list of secrets: Gitleaks puts each one in the
// result's snippet. The findings normalized from data say which results those are
// (findings[i] came from the i-th result), so only those snippets are blanked and
// the rest of the report is kept byte-for-byte when there is nothing to remove.
//
// It never returns the input unchanged when it could not do its job: if the
// results cannot be lined up with the findings, every snippet is blanked, and
// output that is not SARIF is pattern-masked as a whole.
func ScrubRaw(format string, data []byte, findings []model.Finding) []byte {
	anySecret := false
	for _, f := range findings {
		if f.IsSecret() {
			anySecret = true
			break
		}
	}
	if !anySecret {
		return data
	}
	doc, ok := decodeJSON(data)
	if !ok {
		return withheldRaw("raw output held credentials and could not be parsed for redaction", len(data))
	}
	if format == "" || strings.EqualFold(format, "sarif") {
		if scrubSARIF(doc, findings) {
			return encodeJSON(doc, data)
		}
	}
	// Not SARIF (or not shaped like it): no structure to go by, so mask by pattern.
	return encodeJSON(maskStrings(doc), data)
}

// scrubSARIF blanks the snippets of the results that produced credential findings.
// It reports false if doc is not a SARIF log.
func scrubSARIF(doc any, findings []model.Finding) bool {
	root, ok := doc.(map[string]any)
	if !ok {
		return false
	}
	runs, ok := root["runs"].([]any)
	if !ok {
		return false
	}
	var results []map[string]any
	for _, r := range runs {
		run, _ := r.(map[string]any)
		rs, _ := run["results"].([]any)
		for _, x := range rs {
			if res, ok := x.(map[string]any); ok {
				results = append(results, res)
			}
		}
	}
	aligned := len(results) == len(findings)
	for i, res := range results {
		// When the counts disagree we cannot say which result is which finding;
		// blank them all rather than guess.
		if !aligned || findings[i].IsSecret() {
			scrubResult(res)
		}
	}
	return true
}

func scrubResult(res map[string]any) {
	for _, key := range []string{"locations", "relatedLocations"} {
		locs, _ := res[key].([]any)
		for _, l := range locs {
			loc, _ := l.(map[string]any)
			phys, _ := loc["physicalLocation"].(map[string]any)
			for _, rk := range []string{"region", "contextRegion"} {
				region, _ := phys[rk].(map[string]any)
				if snip, ok := region["snippet"].(map[string]any); ok {
					snip["text"] = redact.Mask
					delete(snip, "rendered")
					delete(snip, "binary")
				}
			}
		}
	}
	// Some tools repeat the match in free-form properties.
	if props, ok := res["properties"].(map[string]any); ok {
		res["properties"] = maskStrings(props)
	}
}

// maskStrings pattern-masks every string in a decoded JSON value.
func maskStrings(v any) any {
	switch t := v.(type) {
	case string:
		return redact.Secrets(t)
	case []any:
		for i := range t {
			t[i] = maskStrings(t[i])
		}
		return t
	case map[string]any:
		for k, val := range t {
			t[k] = maskStrings(val)
		}
		return t
	}
	return v
}

func decodeJSON(data []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep numbers exactly as the tool wrote them
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	return doc, true
}

func encodeJSON(doc any, original []byte) []byte {
	b, err := json.Marshal(doc)
	if err != nil {
		return withheldRaw("raw output held credentials and could not be re-encoded after redaction", len(original))
	}
	return b
}

func withheldRaw(why string, n int) []byte {
	b, _ := json.Marshal(map[string]any{"withheld": why, "bytes": n})
	return b
}

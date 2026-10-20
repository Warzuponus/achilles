package llm

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAnthropicSchema_AdaptsToStructuredOutputs(t *testing.T) {
	in := json.RawMessage(`{
	  "type":"object",
	  "properties":{
	    "pattern":{"type":"string","minLength":1},
	    "minimum":{"type":"integer","minimum":0,"maximum":10},
	    "tags":{"type":"array","minItems":3,"maxItems":5,"items":{"type":"object","properties":{"x":{"type":"number"}}}},
	    "one":{"type":"array","minItems":1,"items":{"type":"string"}},
	    "either":{"anyOf":[{"type":"object","properties":{}},{"type":"null"}]}
	  },
	  "required":["pattern"]
	}`)
	var got any
	if err := json.Unmarshal(anthropicSchema(in), &got); err != nil {
		t.Fatal(err)
	}
	var want any
	_ = json.Unmarshal([]byte(`{
	  "type":"object",
	  "properties":{
	    "pattern":{"type":"string"},
	    "minimum":{"type":"integer"},
	    "tags":{"type":"array","items":{"type":"object","properties":{"x":{"type":"number"}},"additionalProperties":false}},
	    "one":{"type":"array","minItems":1,"items":{"type":"string"}},
	    "either":{"anyOf":[{"type":"object","properties":{},"additionalProperties":false},{"type":"null"}]}
	  },
	  "required":["pattern"],
	  "additionalProperties":false
	}`), &want)
	if !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", " ")
		t.Errorf("adapted schema:\n%s", g)
	}
}

func TestAnthropicSchema_UnparseablePassesThrough(t *testing.T) {
	in := json.RawMessage(`{not json`)
	if got := anthropicSchema(in); string(got) != string(in) {
		t.Errorf("got %s", got)
	}
}

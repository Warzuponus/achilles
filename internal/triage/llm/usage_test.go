package llm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIClient_ParsesUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"model":"m","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150}}`)
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "", "m")
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Usage.PromptTokens != 120 || resp.Usage.CompletionTokens != 30 || resp.Usage.TotalTokens != 150 {
		t.Errorf("usage not parsed: %+v", resp.Usage)
	}
}

func TestUsage_Add(t *testing.T) {
	var u Usage
	u.Add(Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15})
	u.Add(Usage{PromptTokens: 1, CompletionTokens: 2, TotalTokens: 3})
	if u != (Usage{PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18}) {
		t.Errorf("Add accumulated wrong: %+v", u)
	}
}

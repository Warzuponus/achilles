package knowledge

import (
	"context"
	"encoding/json"
	"fmt"

	chromem "github.com/philippgille/chromem-go"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
)

// RAG is retrieval-augmented triage memory (DESIGN.md §8): it stores the code
// context of past findings alongside their human label, and retrieves the most
// similar ones at triage time as few-shot examples. Backed by chromem-go
// (pure-Go, embeddable) with an injectable embedding function.
type RAG struct {
	coll *chromem.Collection
}

// NewRAG creates an in-memory RAG collection using the given embedding function.
// For production pass an OpenAI-compatible embedder; tests inject a fake.
func NewRAG(embed chromem.EmbeddingFunc) (*RAG, error) {
	db := chromem.NewDB()
	coll, err := db.CreateCollection("findings", nil, embed)
	if err != nil {
		return nil, fmt.Errorf("create rag collection: %w", err)
	}
	return &RAG{coll: coll}, nil
}

// NewRAGOpenAI builds a RAG backed by an OpenAI-compatible embeddings endpoint
// (keeps chromem out of callers). base_url/api_key are shared with the LLM.
func NewRAGOpenAI(baseURL, apiKey, model string) (*RAG, error) {
	return NewRAG(chromem.NewEmbeddingFuncOpenAICompat(baseURL, apiKey, model, nil))
}

// PopulateFromVault seeds the RAG with every past finding that has analyst
// feedback, using the finding's stored code context. Returns how many were added.
func (r *RAG) PopulateFromVault(ctx context.Context, v vault.Store) (int, error) {
	recs := v.All()

	contexts := map[string]model.Finding{}
	for _, rec := range recs {
		if rec.Kind != vault.KindFinding {
			continue
		}
		var f model.Finding
		if json.Unmarshal(rec.Payload, &f) == nil {
			contexts[f.Fingerprint] = f
		}
	}

	n := 0
	for _, fb := range decodeFeedback(recs) {
		f, ok := contexts[fb.Fingerprint]
		if !ok {
			continue
		}
		if err := r.Add(ctx, f, fb.Label, f.CodeContext); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Add stores a labeled finding's code context for future retrieval.
func (r *RAG) Add(ctx context.Context, f model.Finding, label Label, codeContext string) error {
	if codeContext == "" {
		codeContext = f.Message
	}
	return r.coll.AddDocument(ctx, chromem.Document{
		ID:      f.Fingerprint,
		Content: codeContext,
		Metadata: map[string]string{
			"label": string(label),
			"tool":  f.Tool,
			"rule":  f.RuleID,
		},
	})
}

// Similar returns up to k few-shot example strings for a code context, or nil
// when the corpus is empty. Implements triage.ExampleRetriever.
func (r *RAG) Similar(ctx context.Context, codeContext string, k int) ([]string, error) {
	n := r.coll.Count()
	if n == 0 || codeContext == "" {
		return nil, nil
	}
	if k > n {
		k = n
	}
	results, err := r.coll.Query(ctx, codeContext, k, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("rag query: %w", err)
	}
	out := make([]string, 0, len(results))
	for _, res := range results {
		out = append(out, fmt.Sprintf("Similar past finding (analyst ruled %s, rule %s):\n%s",
			res.Metadata["label"], res.Metadata["rule"], res.Content))
	}
	return out, nil
}

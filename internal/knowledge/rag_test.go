package knowledge

import (
	"context"
	"math"
	"strings"
	"testing"
	"unicode"

	"github.com/Warzuponus/achilles/internal/model"
)

// fakeEmbed is a deterministic bag-of-words embedder: it hashes tokens into a
// fixed-dim vector and L2-normalizes, so texts sharing words are cosine-similar.
// Good enough to test retrieval ranking without a real embedding model.
func fakeEmbed(_ context.Context, text string) ([]float32, error) {
	const dim = 64
	v := make([]float32, dim)
	for _, tok := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		var h uint32 = 2166136261
		for _, c := range tok {
			h = (h ^ uint32(c)) * 16777619
		}
		v[h%dim]++
	}
	var norm float64
	for _, x := range v {
		norm += float64(x) * float64(x)
	}
	if norm == 0 {
		v[0] = 1 // avoid a zero vector
		return v, nil
	}
	norm = math.Sqrt(norm)
	for i := range v {
		v[i] = float32(float64(v[i]) / norm)
	}
	return v, nil
}

func TestRAG_RetrievesMostSimilar(t *testing.T) {
	rag, err := NewRAG(fakeEmbed)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := rag.Add(ctx, model.Finding{Fingerprint: "fp1", Tool: "opengrep", RuleID: "eval"}, LabelFP,
		"eval on user input is dangerous code execution"); err != nil {
		t.Fatal(err)
	}
	if err := rag.Add(ctx, model.Finding{Fingerprint: "fp2", Tool: "gosec", RuleID: "sqli"}, LabelTP,
		"sql query built by string concatenation"); err != nil {
		t.Fatal(err)
	}

	examples, err := rag.Similar(ctx, "user input passed straight into eval", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(examples) != 1 {
		t.Fatalf("want 1 example, got %d", len(examples))
	}
	if !strings.Contains(examples[0], "false_positive") || !strings.Contains(examples[0], "eval") {
		t.Errorf("expected the eval/FP example to rank first, got:\n%s", examples[0])
	}
}

func TestRAG_EmptyCorpus(t *testing.T) {
	rag, err := NewRAG(fakeEmbed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rag.Similar(context.Background(), "anything", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("empty corpus should return nil, got %v", got)
	}
}

package knowledge

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"unicode"

	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/vault"
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

// A credential finding is never a few-shot example: its context is the secret, and
// an example is sent to the embeddings endpoint and later pasted into other
// findings' prompts.
func TestRAG_PopulateFromVaultSkipsCredentialFindings(t *testing.T) {
	v := newVault(t)
	secretText := "hunter" + "2-Xy7!q"
	put := func(f model.Finding) {
		b, _ := json.Marshal(f)
		if _, err := v.Append(vault.Record{RunID: "r", Kind: vault.KindFinding, Fingerprint: f.Fingerprint, Payload: b}); err != nil {
			t.Fatal(err)
		}
		if err := NewFeedbackStore(v).Record("r", Feedback{Fingerprint: f.Fingerprint, Tool: f.Tool, RuleID: f.RuleID, Label: LabelFP}); err != nil {
			t.Fatal(err)
		}
	}
	// As an older vault could hold it: the snippet still on the record.
	put(model.Finding{Fingerprint: "sec", Tool: "gitleaks", RuleID: "generic-api-key", CodeContext: "pw: " + secretText})
	put(model.Finding{Fingerprint: "sec2", Tool: "Trivy", RuleID: "slack-web-hook", Category: model.CategorySecret, CodeContext: secretText})
	put(model.Finding{Fingerprint: "code", Tool: "opengrep", RuleID: "eval", CodeContext: "eval(user_input)"})

	var embedded []string
	rag, err := NewRAG(func(ctx context.Context, text string) ([]float32, error) {
		embedded = append(embedded, text)
		return fakeEmbed(ctx, text)
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := rag.PopulateFromVault(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("seeded %d example(s), want 1 (only the code finding)", n)
	}
	for _, text := range embedded {
		if strings.Contains(text, secretText) {
			t.Errorf("a credential was sent to the embeddings function: %q", text)
		}
	}
}

func TestRAG_AddMasksCredentialsInExamples(t *testing.T) {
	key := "AKIA" + "IOSFODNN7EXAMPLE"
	var embedded []string
	rag, err := NewRAG(func(ctx context.Context, text string) ([]float32, error) {
		embedded = append(embedded, text)
		return fakeEmbed(ctx, text)
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := rag.Add(ctx, model.Finding{Fingerprint: "fp", Tool: "opengrep", RuleID: "eval"}, LabelTP,
		"client = connect(key='"+key+"')\neval(user_input)"); err != nil {
		t.Fatal(err)
	}
	ex, err := rag.Similar(ctx, "eval(user_input)", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range append(embedded, ex...) {
		if strings.Contains(text, key) {
			t.Errorf("a key in ordinary code context must be masked before it is embedded or replayed: %q", text)
		}
	}
	if len(ex) != 1 || !strings.Contains(ex[0], "eval(user_input)") {
		t.Errorf("the example itself should survive masking: %v", ex)
	}
}

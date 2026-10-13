package normalize

import (
	"encoding/json"
	"strings"
	"testing"
)

// gitleaksHistoryDoc is the shape gitleaks emits. In its git mode each result names the
// commit in partialFingerprints; in directory mode the same keys are present and
// empty.
func gitleaksHistoryDoc(results ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "gitleaks"}}, "results": results,
	}}})
	return b
}

func gitleaksHistoryResult(file string, line int, secret, sha, date string) map[string]any {
	return map[string]any{
		"ruleId":  "github-pat",
		"message": map[string]any{"text": "github-pat has detected secret for file " + file + " at commit " + sha + "."},
		"locations": []any{map[string]any{"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": file},
			"region":           map[string]any{"startLine": line, "snippet": map[string]any{"text": secret}},
		}}},
		"partialFingerprints": map[string]any{
			"commitSha": sha, "date": date, "author": "Some One", "email": "someone@example.invalid", "commitMessage": "add token",
		},
	}
}

const (
	shaA = "689bd12734c6a21c4431adae399f29b9d181649b"
	shaB = "b46276dfc79202de8e333a751ca1d4cba321a809"
)

func TestFromSARIF_FindingInACommit(t *testing.T) {
	secret := testSecretA
	fs, err := FromSARIF("gitleaks-history", gitleaksHistoryDoc(
		gitleaksHistoryResult("app.py", 2, secret, shaA, "2026-10-13T03:57:18Z"),
		gitleaksHistoryResult("app.py", 2, secret, shaB, "2026-10-14T08:00:00Z"), // the same line, re-added later
		gitleaksHistoryResult("app.py", 2, secret, "", ""),                       // directory mode: in the files now
	))
	if err != nil || len(fs) != 3 {
		t.Fatalf("findings = %d, err = %v", len(fs), err)
	}
	first, later, inTree := fs[0], fs[1], fs[2]

	if first.Commit != shaA || first.CommitDate != "2026-10-13T03:57:18Z" {
		t.Errorf("commit = %q date = %q", first.Commit, first.CommitDate)
	}
	if inTree.Commit != "" || inTree.CommitDate != "" {
		t.Errorf("a finding in the files must not carry a commit: %q", inTree.Commit)
	}
	// The message says what deleting the line does not fix, names the commit, and
	// carries nothing about who committed it.
	for _, want := range []string{"689bd12", "2026-10-13", "git history", "revoke"} {
		if !strings.Contains(first.Message, want) {
			t.Errorf("message lacks %q: %s", want, first.Message)
		}
	}
	for _, leak := range []string{secret, "someone@example.invalid", "Some One", "add token"} {
		if strings.Contains(first.Message, leak) {
			t.Errorf("message carries %q: %s", leak, first.Message)
		}
	}
	if !strings.Contains(inTree.Message, "has detected secret") {
		t.Errorf("a working-tree finding keeps the scanner's message: %s", inTree.Message)
	}

	// One credential, wherever it was found: the fingerprints agree, which is how a
	// history finding is recognized as the same leak as the one still in a file.
	if first.Fingerprint != inTree.Fingerprint || first.Fingerprint != later.Fingerprint {
		t.Errorf("fingerprints differ: %s %s %s", first.Fingerprint, later.Fingerprint, inTree.Fingerprint)
	}
	// Three places, three identities.
	if first.ID == later.ID || first.ID == inTree.ID || later.ID == inTree.ID {
		t.Errorf("ids collide: %s %s %s", first.ID, later.ID, inTree.ID)
	}
	if !first.IsSecret() {
		t.Error("a history finding from gitleaks is a credential finding")
	}
}

// The commit comes from a file a scanner wrote, or one handed to --from-sarif. Only
// something that looks like a commit id is taken as one.
func TestFromSARIF_CommitMustLookLikeOne(t *testing.T) {
	for _, bad := range []string{"HEAD", "not-a-sha", "689bd1", "689bd12; rm -rf /", strings.Repeat("a", 65)} {
		fs, err := FromSARIF("gitleaks", gitleaksHistoryDoc(gitleaksHistoryResult("a.py", 1, testSecretB, bad, "2026-10-13T03:57:18Z")))
		if err != nil || len(fs) != 1 {
			t.Fatalf("%q: %d findings, err = %v", bad, len(fs), err)
		}
		if fs[0].Commit != "" {
			t.Errorf("%q was accepted as a commit", bad)
		}
	}
	// An upper-case id is the same commit; a date that is not a date is dropped.
	fs, _ := FromSARIF("gitleaks", gitleaksHistoryDoc(gitleaksHistoryResult("a.py", 1, testSecretB, strings.ToUpper(shaA), "yesterday")))
	if fs[0].Commit != shaA || fs[0].CommitDate != "" || strings.Contains(fs[0].Message, "yesterday") {
		t.Errorf("commit = %q date = %q message = %s", fs[0].Commit, fs[0].CommitDate, fs[0].Message)
	}
}

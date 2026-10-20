package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

// Opengrep fills in "$X" and "$1" in a rule's message with what the match bound,
// so a message that shows example code with "$1" in it came out with a piece of the
// scanned file there instead, different for each copy of the finding.
func TestRuleMessagesHaveNoMetavariables(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "configs", "rules", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no rule files: %v", err)
	}
	metavar := regexp.MustCompile(`\$([0-9]+|[A-Z_][A-Z0-9_]*\b)`)
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []struct {
				ID      string `yaml:"id"`
				Message string `yaml:"message"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for _, r := range doc.Rules {
			if m := metavar.FindString(r.Message); m != "" {
				t.Errorf("%s: %s: message contains %q, which Opengrep replaces with matched text", filepath.Base(p), r.ID, m)
			}
		}
	}
}

package triage

import (
	"strings"
	"testing"

	"github.com/Warzuponus/achilles/internal/model"
)

// The AI-model guidance reaches the triage and judge prompts only for a finding
// that involves a model, so other findings pay nothing for it.
func TestModelGuidance_OnlyForAIModelFindings(t *testing.T) {
	plain := model.Finding{Tool: "opengrep", RuleID: "python.sqli", Location: model.Location{File: "db.py"}}
	for name, tc := range map[string]struct {
		f    model.Finding
		code string
		want bool
	}{
		"llm rule":           {model.Finding{RuleID: "achilles.llm.python.output-to-sql"}, "", true},
		"cwe":                {model.Finding{RuleID: "x", CWE: []string{"CWE-1427"}}, "", true},
		"code calls openai":  {plain, "3 | resp = client.chat.completions.create(model=m)", true},
		"langchain import":   {plain, "1 | from langchain_openai import ChatOpenAI", true},
		"plain":              {plain, "4 | cursor.execute(q)", false},
		"maintain is not ai": {model.Finding{RuleID: "maintainability.long-function"}, "", false},
		"leaked key":         {model.Finding{Tool: "gitleaks", RuleID: "openai-api-key"}, "OPENAI_KEY = ...", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := modelGuidance(tc.f, tc.code) != ""; got != tc.want {
				t.Errorf("guidance = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestModelGuidance_InTriageAndJudgePrompts(t *testing.T) {
	f := model.Finding{Tool: "opengrep", RuleID: "achilles.llm.python.output-to-code-execution"}
	tri := triageMessages(f, "x", nil)[0].Content
	jud := judgeMessages(f, "x", model.Verdict{Classification: model.ClassTruePositive}, false)[0].Content
	for name, sys := range map[string]string{"triage": tri, "judge": jud} {
		if !strings.Contains(sys, "A prompt that can be steered is not by itself a vulnerability") {
			t.Errorf("%s prompt lacks the AI-model guidance", name)
		}
	}
	f.RuleID = "python.sqli"
	if strings.Contains(triageMessages(f, "x", nil)[0].Content, "involves an AI model") {
		t.Error("guidance added to a finding with nothing to do with a model")
	}
}

func TestTriagePrompt_ListsHardeningAsAClassification(t *testing.T) {
	sys := triageMessages(model.Finding{RuleID: "r"}, "x", nil)[0].Content
	if !strings.Contains(sys, `"false_positive", "hardening" or "uncertain"`) {
		t.Error("the JSON key list must allow hardening, or a strict model never uses it")
	}
}

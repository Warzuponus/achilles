// Package knowledge is Achilles's learning layer (DESIGN.md §8): it turns the
// Evidence Vault into a system that gets smarter — capturing analyst feedback,
// calibrating per-rule trust, and retrieving similar past findings for the LLM.
package knowledge

import (
	"encoding/json"

	"github.com/Warzuponus/achilles/internal/vault"
)

// Label is an analyst's ground-truth call on a finding.
type Label string

const (
	LabelTP Label = "true_positive"
	LabelFP Label = "false_positive"
)

// Feedback is one human verdict on a finding, keyed by fingerprint so it links
// to the same finding across scans (even after line drift).
type Feedback struct {
	Fingerprint string `json:"fingerprint"`
	Tool        string `json:"tool"`
	RuleID      string `json:"ruleId"`
	Label       Label  `json:"label"`
	Note        string `json:"note,omitempty"`
}

// FeedbackStore reads and writes feedback through the Evidence Vault.
type FeedbackStore struct {
	v vault.Store
}

func NewFeedbackStore(v vault.Store) *FeedbackStore { return &FeedbackStore{v: v} }

// Record appends a feedback record to the vault.
func (s *FeedbackStore) Record(runID string, fb Feedback) error {
	b, err := json.Marshal(fb)
	if err != nil {
		return err
	}
	_, err = s.v.Append(vault.Record{
		RunID: runID, Phase: "reflect", Kind: vault.KindFeedback,
		Source: fb.Tool, Fingerprint: fb.Fingerprint, Payload: b,
	})
	return err
}

// History returns all feedback recorded for one finding fingerprint.
func (s *FeedbackStore) History(fingerprint string) []Feedback {
	return decodeFeedback(s.v.ByFingerprint(fingerprint))
}

// All returns every feedback record in the vault (the calibration corpus).
func (s *FeedbackStore) All() []Feedback {
	return decodeFeedback(s.v.All())
}

func decodeFeedback(recs []vault.Record) []Feedback {
	var out []Feedback
	for _, r := range recs {
		if r.Kind != vault.KindFeedback {
			continue
		}
		var fb Feedback
		if err := json.Unmarshal(r.Payload, &fb); err == nil {
			out = append(out, fb)
		}
	}
	return out
}

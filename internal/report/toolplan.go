package report

import (
	"fmt"
	"strings"

	"github.com/Warzuponus/achilles/internal/model"
)

// toolPlanHeader is the scan depth line of the scan plan.
func toolPlanHeader(p *model.ToolPlan) string {
	if p.Depth == "" {
		return "Scan plan"
	}
	s := "Scan plan: depth " + p.Depth
	if len(p.DepthReasons) > 0 {
		s += " (" + strings.Join(p.DepthReasons, "; ") + ")"
	}
	if p.AllTools {
		s += "; --all-tools: no scanner skipped"
	}
	return s
}

// toolPlanLines are the scan plan's decisions, one per line: every scanner it
// skipped or added, with the reason, and what it recommends.
func toolPlanLines(p *model.ToolPlan) []string {
	var out []string
	for _, d := range p.Decisions {
		switch d.Action {
		case model.ToolSkipped:
			line := fmt.Sprintf("skipped %s: %s", d.Tool, d.Reason)
			if d.Fix != "" {
				line += " (" + d.Fix + " runs it)"
			}
			out = append(out, line)
		case model.ToolAdded:
			out = append(out, fmt.Sprintf("added %s: %s", d.Tool, d.Reason))
		case model.ToolRecommended:
			out = append(out, fmt.Sprintf("recommends %s: %s", d.Tool, d.Reason))
		}
	}
	return out
}

// toolPlanNotifications are the SARIF notifications for the scanners the plan
// skipped or added, so a code-scanning reader sees why a scanner has no results.
func toolPlanNotifications(p *model.ToolPlan) []model.SarifNotification {
	if p == nil {
		return nil
	}
	var out []model.SarifNotification
	for _, d := range p.Decisions {
		var text string
		switch d.Action {
		case model.ToolSkipped:
			text = "the scan plan skipped " + d.Tool + ": " + d.Reason
			if d.Fix != "" {
				text += " (" + d.Fix + " runs it)"
			}
		case model.ToolAdded:
			text = "the scan plan added " + d.Tool + ": " + d.Reason
		default:
			continue
		}
		out = append(out, model.SarifNotification{Level: "note", Message: model.SarifMessage{Text: text}})
	}
	return out
}

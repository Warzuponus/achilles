package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Warzuponus/achilles/internal/gitlab"
	"github.com/Warzuponus/achilles/internal/model"
	"github.com/Warzuponus/achilles/internal/report"
)

// runGitLabMRComment posts (or updates) the sticky Markdown summary as a note on a
// GitLab merge request. Outward-facing and opt-in, like --pr-comment. The token is
// ACHILLES_GITLAB_TOKEN (or GITLAB_TOKEN): a personal, project or group access
// token with the api scope. CI_JOB_TOKEN cannot write notes, so it is not used.
func runGitLabMRComment(ctx context.Context, mr int, project string, scan model.Scan) error {
	var md strings.Builder
	if err := report.WriteMarkdown(&md, scan); err != nil {
		return err
	}
	gc, err := gitlab.New(envOr("ACHILLES_GITLAB_TOKEN", os.Getenv("GITLAB_TOKEN")), project, os.Getenv("CI_API_V4_URL"))
	if err != nil {
		return err
	}
	created, err := gc.UpsertMergeRequestNote(ctx, mr, "mr-summary", md.String())
	if err != nil {
		return err
	}
	action := "updated"
	if created {
		action = "created"
	}
	fmt.Fprintf(os.Stderr, "achilles: gitlab-mr-comment — %s sticky summary on %s!%d\n", action, project, mr)
	return nil
}

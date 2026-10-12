package main

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/Warzuponus/achilles/internal/triage/llm"
)

// announceEgress says, before any code leaves the machine, where it is going and
// what is sent. Source snippets go to the LLM endpoint; people who never read the
// docs should still be told. tasks is the --model-config routing: a task there may
// name its own endpoint, and that one receives code too.
func announceEgress(w io.Writer, o *options, tasks map[string]llm.TaskModel) {
	host := hostOf(o.llmBaseURL)
	if o.llmNoCode {
		fmt.Fprintf(w, "achilles: AI features on — sending rule names, messages and file locations to %s (no source code: --llm-no-code)\n", host)
	} else {
		fmt.Fprintf(w, "achilles: AI features on — code around each finding (with credentials masked; credential findings withheld) will be sent to %s. "+
			"Use --llm-no-code to send no source, or a local model (--llm-provider ollama) to keep code on this machine.\n", host)
	}
	if extra := taskEndpoints(tasks, host); len(extra) > 0 {
		fmt.Fprintf(w, "achilles: --model-config also sends to: %s\n", strings.Join(extra, "; "))
	}
}

func hostOf(baseURL string) string {
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		return u.Host
	}
	return baseURL
}

// taskEndpoints lists, as "host (task, task)", every endpoint the routing names
// other than the main one, in a stable order.
func taskEndpoints(tasks map[string]llm.TaskModel, mainHost string) []string {
	byHost := map[string][]string{}
	for name, tm := range tasks {
		if tm.BaseURL == "" {
			continue
		}
		if h := hostOf(tm.BaseURL); h != mainHost {
			byHost[h] = append(byHost[h], name)
		}
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		sort.Strings(byHost[h])
		out = append(out, fmt.Sprintf("%s (%s)", h, strings.Join(byHost[h], ", ")))
	}
	return out
}

// checkTaskEndpoints applies the same pre-flight to each endpoint named in
// --model-config that --llm-base-url gets. The API key from the environment is sent
// to those endpoints as well, so a plain-http URL or another provider's host there
// leaks it exactly as a wrong --llm-base-url would, and used to go unchecked.
func checkTaskEndpoints(tasks map[string]llm.TaskModel, authMode, apiKey string) error {
	names := make([]string, 0, len(tasks))
	for name := range tasks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if base := tasks[name].BaseURL; base != "" {
			if err := llm.CheckEndpoint(base, authMode, apiKey); err != nil {
				return fmt.Errorf("--model-config, task %q (baseURL %s): %w", name, base, err)
			}
		}
	}
	return nil
}

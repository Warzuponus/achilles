package main

import (
	"fmt"
	"io"
	"net/url"
)

// announceEgress says, before any code leaves the machine, where it is going and
// what is sent. Source snippets go to the LLM endpoint; people who never read the
// docs should still be told.
func announceEgress(w io.Writer, o *options) {
	host := o.llmBaseURL
	if u, err := url.Parse(o.llmBaseURL); err == nil && u.Host != "" {
		host = u.Host
	}
	if o.llmNoCode {
		fmt.Fprintf(w, "achilles: AI features on — sending rule names, messages and file locations to %s (no source code: --llm-no-code)\n", host)
		return
	}
	fmt.Fprintf(w, "achilles: AI features on — code around each finding (with credentials masked; credential findings withheld) will be sent to %s. "+
		"Use --llm-no-code to send no source, or a local model (--llm-provider ollama) to keep code on this machine.\n", host)
}

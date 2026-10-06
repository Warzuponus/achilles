package opengrep

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	xexec "github.com/Warzuponus/achilles/internal/exec"
	"github.com/Warzuponus/achilles/internal/scanner"
)

type recordRunner struct{ got xexec.Command }

func (r *recordRunner) Run(_ context.Context, c xexec.Command) (xexec.Result, error) {
	r.got = c
	// The adapter reads {out}/results.sarif afterwards; write an empty one.
	for _, m := range c.Mounts {
		if m.Name == "out" {
			os.WriteFile(filepath.Join(m.HostPath, "results.sarif"), []byte(`{"runs":[]}`), 0o600)
		}
	}
	return xexec.Result{}, nil
}

func TestExtraRulesAddsSecondDashF(t *testing.T) {
	rr := &recordRunner{}
	s := New(rr, "/base/rules", WithExtraRules("/community"))
	if _, err := s.Run(context.Background(), scanner.Target{Path: "/src"}); err != nil {
		t.Fatal(err)
	}
	wantTail := []string{"-f", "{rules}", "-f", "{rules2}", "{src}"}
	args := rr.got.Args
	if !reflect.DeepEqual(args[len(args)-5:], wantTail) {
		t.Fatalf("args = %v", args)
	}
	hosts := map[string]string{}
	for _, m := range rr.got.Mounts {
		hosts[m.Name] = m.HostPath
	}
	if hosts["rules"] != "/base/rules" || hosts["rules2"] != "/community" {
		t.Fatalf("mounts = %v", hosts)
	}
}

func TestNoExtraRulesKeepsSingleDashF(t *testing.T) {
	rr := &recordRunner{}
	if _, err := New(rr, "/base/rules").Run(context.Background(), scanner.Target{Path: "/src"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range rr.got.Args {
		if a == "-f" {
			n++
		}
	}
	if n != 1 || len(rr.got.Mounts) != 3 {
		t.Fatalf("args=%v mounts=%v", rr.got.Args, rr.got.Mounts)
	}
}

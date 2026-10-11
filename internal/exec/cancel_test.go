package exec

import (
	"context"
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the "scanner": started with ACHILLES_EXEC_HELPER set,
// it behaves like a launcher (which starts a worker and waits) or like the worker
// (which keeps writing a heartbeat file and holds the inherited stdout open).
func TestMain(m *testing.M) {
	switch os.Getenv("ACHILLES_EXEC_HELPER") {
	case "launcher":
		worker := osexec.Command(os.Args[0])
		worker.Env = append(os.Environ(), "ACHILLES_EXEC_HELPER=worker")
		worker.Stdout, worker.Stderr = os.Stdout, os.Stderr // the worker inherits our pipes
		if err := worker.Start(); err != nil {
			os.Exit(3)
		}
		_ = worker.Wait()
		os.Exit(0)
	case "worker":
		beat := os.Getenv("ACHILLES_EXEC_HEARTBEAT")
		for i := 0; i < 600; i++ { // up to a minute: far longer than any test waits
			_ = os.WriteFile(beat, []byte(strconv.Itoa(i)), 0o600)
			time.Sleep(100 * time.Millisecond)
		}
		os.Exit(0)
	case "partial":
		// Writes part of a report, then hangs: a tool cut off mid-scan.
		_, _ = os.Stdout.WriteString(`{"runs":[`)
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func readBeat(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

// The bug: on --timeout or Ctrl-C only the launcher process was killed. Its worker
// kept running and kept the output pipe open, so the wait for the "finished"
// command lasted as long as the worker did, and the scan hung past its timeout.
func TestRunCmd_TimeoutStopsTheWholeProcessTreeAndReturnsPromptly(t *testing.T) {
	beat := filepath.Join(t.TempDir(), "beat")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := runCmd(ctx, os.Args[0], nil, runOpts{extraEnv: []string{
		"ACHILLES_EXEC_HELPER=launcher", "ACHILLES_EXEC_HEARTBEAT=" + beat,
	}})
	elapsed := time.Since(start)

	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want one that says the command timed out", err)
	}
	// Without the fix this takes the worker's full minute.
	if elapsed > 20*time.Second {
		t.Fatalf("runCmd returned after %s; it must not wait for a worker that outlived the launcher", elapsed.Round(time.Millisecond))
	}
	if readBeat(t, beat) == "" {
		t.Fatal("the worker never started, so this test proved nothing")
	}

	// The worker must be dead too, not just abandoned: its heartbeat stops.
	time.Sleep(400 * time.Millisecond)
	before := readBeat(t, beat)
	time.Sleep(1200 * time.Millisecond)
	if after := readBeat(t, beat); after != before {
		t.Errorf("the worker is still running after the timeout (heartbeat %s -> %s)", before, after)
	}
}

func TestRunCmd_OnCancelRunsWhenTheContextEnds(t *testing.T) {
	beat := filepath.Join(t.TempDir(), "beat")
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{}, 1)
	go func() {
		time.Sleep(700 * time.Millisecond)
		cancel() // as Ctrl-C does
	}()
	_, err := runCmd(ctx, os.Args[0], nil, runOpts{
		extraEnv: []string{"ACHILLES_EXEC_HELPER=worker", "ACHILLES_EXEC_HEARTBEAT=" + beat},
		onCancel: func() { called <- struct{}{} },
	})
	if err == nil || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("err = %v, want an interrupted error", err)
	}
	select {
	case <-called:
	default:
		t.Error("onCancel did not run; the docker runner relies on it to kill the container")
	}
}

// A tool killed mid-scan is a failed run, not an exit code for the adapter to
// interpret: it may have written half a report.
func TestRunCmd_AKilledCommandIsAnErrorNotAnExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	res, err := runCmd(ctx, os.Args[0], nil, runOpts{extraEnv: []string{"ACHILLES_EXEC_HELPER=partial"}})
	if err == nil {
		t.Fatalf("a timed-out command returned no error (exit code %d, stdout %q)", res.ExitCode, res.Stdout)
	}
}

func TestRunCmd_NormalExitCodesAreStillTheAdaptersToJudge(t *testing.T) {
	// The launcher exits 3 when it cannot start a worker: point it at nothing.
	res, err := runCmd(context.Background(), os.Args[0], []string{"-test.run=^$"}, runOpts{})
	if err != nil || res.ExitCode != 0 {
		t.Errorf("a command that exits 0: res=%+v err=%v", res, err)
	}
	if _, err := runCmd(context.Background(), "definitely-not-an-installed-binary-xyz", nil, runOpts{}); err == nil {
		t.Error("a missing binary is still a Runner error")
	}
}

func TestDockerRunner_NamesTheContainerSoItCanBeKilled(t *testing.T) {
	a, b := containerName(), containerName()
	if a == b || !strings.HasPrefix(a, "achilles-") || len(a) < len("achilles-")+8 {
		t.Errorf("container names must be unique and recognisable: %q %q", a, b)
	}
}

// `docker run` with an empty image name fails with "invalid reference format",
// which names neither the tool nor the cause.
func TestDockerRunner_NoImageIsAClearError(t *testing.T) {
	_, err := DockerRunner{}.Run(context.Background(), Command{Bin: "tool", Args: []string{"scan"}})
	if err == nil || !strings.Contains(err.Error(), "no container image") {
		t.Errorf("err = %v, want one that says no image is configured", err)
	}
}

package shell_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/antonmedv/ssham/internal/shell"
	"github.com/antonmedv/ssham/internal/shelltest"
)

// Most shell behavior is covered by the transcripts in testdata/. These
// tests cover what a transcript cannot express.

func TestTranscripts(t *testing.T) {
	shelltest.RunTranscripts(t, "testdata/*.txt")
}

func TestSessionsAreIsolated(t *testing.T) {
	a := shelltest.New(t, "root")
	b := shelltest.New(t, "root")
	a.Run("touch /tmp/marker; echo pw > /mnt/mtd/Config/Account")
	out, _ := b.Run("ls /tmp/marker; head -1 /mnt/mtd/Config/Account")
	if !strings.Contains(out, "No such file") || !strings.Contains(out, "[admin]") {
		t.Fatalf("second session saw first session's changes:\n%s", out)
	}
}

func TestReplNestedShellAndExit(t *testing.T) {
	// Any login name gets the device's root shell.
	s := shelltest.New(t, "admin")
	out, status := s.Repl("cd /tmp", "sh", "pwd", "exit", "whoami", "exit 3")
	if status != 3 {
		t.Errorf("status = %d", status)
	}
	want := "~ # cd /tmp\n/tmp # sh\n/tmp # pwd\n/tmp\n/tmp # exit\n/tmp # whoami\nroot\n/tmp # exit 3\n"
	if out != want {
		t.Errorf("got:\n%q\nwant:\n%q", out, want)
	}
	if ev := s.Events("input"); len(ev) != 6 {
		t.Errorf("input events: %v", ev)
	}
}

func TestReplCtrlDIsSilent(t *testing.T) {
	s := shelltest.New(t, "root")
	out, _ := s.Repl("sh")
	// Ctrl+D leaves the nested sh, then logs out; ash prints nothing.
	if out != "~ # sh\n~ # \n~ # \n" {
		t.Errorf("got:\n%q", out)
	}
}

func TestInterruptStopsLongCommand(t *testing.T) {
	s := shelltest.New(t, "root", shelltest.RealSleep())
	done := make(chan int)
	go func() { done <- s.Shell.Exec(context.Background(), "ping 10.0.0.1") }()
	time.Sleep(100 * time.Millisecond)
	s.Shell.Interrupt()
	select {
	case status := <-done:
		if status != 130 {
			t.Errorf("status = %d, want 130", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("command was not interrupted")
	}
}

func TestPanicsAreContained(t *testing.T) {
	boom := shell.Command{Name: "boom", Run: func(*shell.Env) int { panic("bug") }}
	s := shelltest.New(t, "root", shelltest.WithCommands(boom))

	// Like a segfault, the panic ends that command only.
	out, status := s.Run("echo before; boom; echo after")
	if out != "before\nSegmentation fault\nafter\n" || status != 0 {
		t.Errorf("Run: %q %d", out, status)
	}
	out, status = s.Exec("boom")
	if out != "Segmentation fault\n" || status != 139 {
		t.Errorf("Exec: %q %d", out, status)
	}
	if ev := s.Events("panic"); len(ev) != 2 {
		t.Errorf("panic events: %v", ev)
	}
	if out, _ := s.Run("whoami"); out != "root\n" {
		t.Errorf("after panic: %q", out)
	}
}

func TestComplete(t *testing.T) {
	sh := shelltest.New(t, "root").Shell
	tests := []struct {
		line string
		want []string
	}{
		{"whoa", []string{"whoami"}},
		{"cat /etc/host", []string{"/etc/hostname", "/etc/hosts"}},
		{"cd /us", []string{"/usr/"}},
		{"cat /mnt/mtd/Config/A", []string{"/mnt/mtd/Config/Account"}},
		{"echo hi | gre", []string{"grep"}},
		{"curl", nil},
	}
	for _, tt := range tests {
		_, got := sh.Complete(tt.line)
		if strings.Join(got, " ") != strings.Join(tt.want, " ") {
			t.Errorf("Complete(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

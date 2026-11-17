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
	a.Run("rm -rf /etc && touch /tmp/marker")
	out, _ := b.Run("ls /tmp/marker; cat /etc/hostname")
	if !strings.Contains(out, "No such file") || !strings.Contains(out, "ip-10-0-2-15") {
		t.Fatalf("second session saw first session's changes:\n%s", out)
	}
}

func TestReplSudoAndExit(t *testing.T) {
	s := shelltest.New(t, "admin")
	out, status := s.Repl("sudo -i", "hunter2", "whoami", "exit", "whoami", "exit")
	if status != 0 {
		t.Errorf("status = %d", status)
	}
	want := `admin@ip-10-0-2-15:~$ sudo -i
[sudo] password for admin: ` + `
root@ip-10-0-2-15:~# whoami
root
root@ip-10-0-2-15:~# exit
exit
admin@ip-10-0-2-15:~$ whoami
admin
admin@ip-10-0-2-15:~$ exit
`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	if ev := s.Events("password_entered"); len(ev) != 1 || ev[0]["password"] != "hunter2" {
		t.Errorf("password events: %v", ev)
	}
	if ev := s.Events("input"); len(ev) != 5 {
		t.Errorf("input events: %v", ev)
	}
}

func TestReplLogoutOnEOF(t *testing.T) {
	s := shelltest.New(t, "root")
	out, _ := s.Repl("bash", "whoami")
	// Ctrl+D leaves the nested bash first, then the login shell.
	if !strings.HasSuffix(out, "root@ip-10-0-2-15:~# \nexit\nroot@ip-10-0-2-15:~# \n") {
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
	if out != "before\nSegmentation fault (core dumped)\nafter\n" || status != 0 {
		t.Errorf("Run: %q %d", out, status)
	}
	out, status = s.Exec("boom")
	if out != "Segmentation fault (core dumped)\n" || status != 139 {
		t.Errorf("Exec: %q %d", out, status)
	}
	if ev := s.Events("panic"); len(ev) != 2 {
		t.Errorf("panic events: %v", ev)
	}
	// The session still works.
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
		{"ls ~/.ba", []string{"~/.bash_history", "~/.bashrc"}},
		{"echo hi | gre", []string{"grep"}},
	}
	for _, tt := range tests {
		_, got := sh.Complete(tt.line)
		if strings.Join(got, " ") != strings.Join(tt.want, " ") {
			t.Errorf("Complete(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

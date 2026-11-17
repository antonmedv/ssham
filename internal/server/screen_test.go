package server

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/vt"
	gossh "golang.org/x/crypto/ssh"
)

// screenSession runs an interactive session whose output is rendered by a
// terminal emulator, so tests can assert on what a user would actually see.
type screenSession struct {
	t     *testing.T
	emu   *vt.SafeEmulator
	stdin io.Writer
	sess  *gossh.Session
	raw   *syncBuf // every byte the server sent
}

func newScreenSession(t *testing.T, user string, w, h int) *screenSession {
	t.Helper()
	addr, _ := startServer(t)
	c := dial(t, addr, user, "pw")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", h, w, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	// The emulator is sized so the session never scrolls: vt's scrollback
	// path is not safe for concurrent reads.
	ew := w
	if ew <= 0 {
		ew = 80
	}
	emu := vt.NewSafeEmulator(ew, max(h, 60))
	stdin, _ := sess.StdinPipe()
	raw := &syncBuf{}
	sess.Stdout = io.MultiWriter(emu, raw)
	sess.Stderr = sess.Stdout
	// Terminal replies (e.g. to capability queries) go back to the app.
	go func() { _, _ = io.Copy(stdin, emu) }()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// The emulator is not closed: its Close races with a blocked Read.
	t.Cleanup(func() { sess.Close() })
	return &screenSession{t: t, emu: emu, stdin: stdin, sess: sess, raw: raw}
}

func (s *screenSession) screen() string {
	lines := strings.Split(s.emu.String(), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

func (s *screenSession) waitScreen(want string) {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.screen(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.t.Fatalf("timed out waiting for %q on screen:\n%s", want, s.screen())
}

func (s *screenSession) send(keys string) { _, _ = io.WriteString(s.stdin, keys) }

func TestScreenRendering(t *testing.T) {
	s := newScreenSession(t, "admin", 80, 60)
	s.waitScreen("admin@ip-10-0-2-15:~$")
	s.send("echo one\r")
	s.waitScreen("one\nadmin@ip-10-0-2-15:~$")
	s.send("printf 'a\\tb\\n'; echo -n partial\r")
	s.waitScreen("partialadmin@ip-10-0-2-15:~$")
	t.Logf("screen:\n%s", s.screen())
	want := "admin@ip-10-0-2-15:~$ echo one\none\nadmin@ip-10-0-2-15:~$ printf 'a\\tb\\n'; echo -n partial\na       b\npartialadmin@ip-10-0-2-15:~$"
	if !strings.Contains(s.screen(), want) {
		t.Errorf("screen mismatch; want contiguous block:\n%s\n--- got ---\n%s", want, s.screen())
	}
}

func TestScreenLineEditing(t *testing.T) {
	s := newScreenSession(t, "admin", 60, 40)
	prompt := "admin@ip-10-0-2-15:~$"
	s.waitScreen(prompt)

	// sudo password is hidden, then the command runs as root.
	s.send("sudo whoami\r")
	s.waitScreen("[sudo] password for admin:")
	s.send("s3cret\r")
	s.waitScreen("[sudo] password for admin:\nroot\n" + prompt)
	if strings.Contains(s.screen(), "s3cret") {
		t.Errorf("password was echoed:\n%s", s.screen())
	}

	// History recall with the up arrow.
	s.send("\x1b[A\x1b[A\r")
	s.waitScreen("root\n" + prompt + " sudo whoami\nroot\n" + prompt)

	// Ctrl+C at the prompt abandons the line.
	s.send("abandoned\x03")
	s.waitScreen(prompt + " abandoned^C\n" + prompt)

	// A long line wraps at the terminal width instead of being cut off.
	long := "echo " + strings.Repeat("x", 70)
	s.send(long + "\r")
	s.waitScreen(strings.Repeat("x", 60) + "\n" + strings.Repeat("x", 10) + "\n" + prompt)

	// Double Tab lists candidates.
	s.send("cat /etc/host\t\t")
	s.waitScreen("hostname  hosts")
	s.send("\x15") // Ctrl+U clears the line

	// A multi-line paste runs each line in order.
	s.send("\x1b[200~echo p1\necho p2\n\x1b[201~")
	s.waitScreen("p1\n" + prompt + " echo p2\np2\n" + prompt)

	// clear (and Ctrl+L) wipe the screen.
	s.send("clear\r")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && strings.Contains(s.screen(), "p1") {
		time.Sleep(20 * time.Millisecond)
	}
	if got := s.screen(); strings.Contains(got, "p1") || !strings.HasPrefix(got, prompt) {
		t.Errorf("screen not cleared:\n%s", got)
	}

	// Output after a clear lands right below the prompt.
	s.send("echo after\r")
	s.waitScreen(prompt + " echo after\nafter\n" + prompt)

	// Ctrl+L clears but keeps the line being edited.
	s.send("echo kept\x0c")
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.screen() != prompt+" echo kept" {
		time.Sleep(20 * time.Millisecond)
	}
	if got := s.screen(); got != prompt+" echo kept" {
		t.Errorf("after Ctrl+L got:\n%s", got)
	}
	s.send("\r")
	s.waitScreen(prompt + " echo kept\nkept\n" + prompt)
}

func TestNoFingerprintSequencesAndIdleIsQuiet(t *testing.T) {
	s := newScreenSession(t, "root", 80, 50)
	s.waitScreen("root@ip-10-0-2-15:~#")
	s.send("echo hi\r")
	s.waitScreen("hi\nroot@ip-10-0-2-15:~#")

	before := len(s.raw.String())
	time.Sleep(500 * time.Millisecond)
	if after := len(s.raw.String()); after != before {
		t.Errorf("server sent %d bytes while idle: %q", after-before, s.raw.String()[before:])
	}

	s.send("exit\r")
	_ = s.sess.Wait()
	if m := fingerprintSeqs.FindAllString(s.raw.String(), -1); len(m) > 0 {
		t.Errorf("raw output contains non-bash escape sequences: %q", m)
	}
}

func TestZeroSizePty(t *testing.T) {
	s := newScreenSession(t, "root", 0, 0)
	before := time.Now()
	for time.Since(before) < 2*time.Second && !strings.Contains(s.raw.String(), "root@ip-10-0-2-15") {
		time.Sleep(20 * time.Millisecond)
	}
	n := len(s.raw.String())
	time.Sleep(500 * time.Millisecond)
	if d := len(s.raw.String()) - n; d > 0 {
		t.Errorf("server sent %d bytes while idle on a 0x0 pty", d)
	}
}

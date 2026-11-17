package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	gossh "golang.org/x/crypto/ssh"

	"github.com/antonmedv/ssham/internal/audit"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startServer(t *testing.T) (addr string, auditLog *syncBuf) {
	t.Helper()
	auditLog = &syncBuf{}
	srv, err := New(Config{
		Addr:        "127.0.0.1:0",
		HostKeyPath: filepath.Join(t.TempDir(), "hostkey"),
		Hostname:    "ip-10-0-2-15",
		Kernel:      "6.8.0-48-generic",
		Version:     "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		MaxSessions: 4,
		Audit:       audit.New(auditLog),
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return l.Addr().String(), auditLog
}

func dial(t *testing.T, addr, user, password string) *gossh.Client {
	t.Helper()
	c, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestExecAndCredentialLogging(t *testing.T) {
	addr, log := startServer(t)
	c := dial(t, addr, "root", "toor123")
	if v := string(c.ServerVersion()); v != "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" {
		t.Errorf("server version = %q", v)
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.CombinedOutput("uname -a; whoami; cat /etc/shadow | head -1 | cut -d: -f1")
	if err != nil {
		t.Fatalf("exec: %v\n%s", err, out)
	}
	want := "Linux ip-10-0-2-15 6.8.0-48-generic"
	if !strings.Contains(string(out), want) || !strings.Contains(string(out), "\nroot\nroot\n") {
		t.Errorf("unexpected output:\n%s", out)
	}

	sess, _ = c.NewSession()
	err = sess.Run("exit 7")
	var exitErr *gossh.ExitError
	if !asExit(err, &exitErr) || exitErr.ExitStatus() != 7 {
		t.Errorf("exit status: %v", err)
	}

	logs := log.String()
	for _, w := range []string{`"msg":"auth"`, `"password":"toor123"`, `"user":"root"`, `"line":"uname -a; whoami;`} {
		if !strings.Contains(logs, w) {
			t.Errorf("audit log missing %s\n%s", w, logs)
		}
	}
}

func asExit(err error, target **gossh.ExitError) bool {
	e, ok := err.(*gossh.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func TestAnyPublicKeyAcceptedAndLogged(t *testing.T) {
	addr, log := startServer(t)
	_, priv, _ := ed25519Key()
	signer, _ := gossh.NewSignerFromKey(priv)
	c, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "deploy",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("public key login rejected: %v", err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.CombinedOutput("whoami")
	if err != nil || string(out) != "deploy\n" {
		t.Errorf("whoami = %q, %v", out, err)
	}
	logs := log.String()
	for _, w := range []string{`"method":"publickey"`, `"success":true`, `"fingerprint":"` + gossh.FingerprintSHA256(signer.PublicKey()) + `"`, `"key":"ssh-ed25519 `} {
		if !strings.Contains(logs, w) {
			t.Errorf("audit log missing %s\n%s", w, logs)
		}
	}
}

// waitFor reads until the ANSI-stripped output contains want.
func waitFor(t *testing.T, out *syncBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(ansi.Strip(out.String()), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q; got:\n%s", want, ansi.Strip(out.String()))
}

func TestInteractiveShell(t *testing.T) {
	addr, log := startServer(t)
	c := dial(t, addr, "admin", "admin")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 40, 120, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	out := &syncBuf{}
	sess.Stdout = out
	sess.Stderr = out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	waitFor(t, out, "Welcome to Ubuntu 24.04.1 LTS")
	waitFor(t, out, "admin@ip-10-0-2-15:~$")

	io.WriteString(stdin, "echo $((6*7))\r")
	waitFor(t, out, "\n42")

	// Tab completion of a command name.
	io.WriteString(stdin, "whoa\t\r")
	waitFor(t, out, "$ whoami")
	waitFor(t, out, "\nadmin")

	// Line editing: type, move left, insert.
	io.WriteString(stdin, "eco hi\x1b[D\x1b[D\x1b[D\x1b[Dh\r")
	waitFor(t, out, "\nhi")

	// Ctrl+C interrupts a running command.
	io.WriteString(stdin, "sleep 30\r")
	time.Sleep(200 * time.Millisecond)
	io.WriteString(stdin, "\x03")
	io.WriteString(stdin, "echo after-$?\r")
	waitFor(t, out, "after-130")

	io.WriteString(stdin, "exit\r")
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not end after exit")
	}
	if !strings.Contains(ansi.Strip(out.String()), "logout") {
		t.Errorf("no logout message:\n%s", ansi.Strip(out.String()))
	}
	for _, w := range []string{`"line":"echo $((6*7))"`, `"line":"whoami "`, `"msg":"session_end"`} {
		if !strings.Contains(log.String(), w) {
			t.Errorf("audit log missing %s", w)
		}
	}
}

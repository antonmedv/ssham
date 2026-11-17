package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	gossh "golang.org/x/crypto/ssh"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/crypt"
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
	addr, auditLog, _ = startServerWith(t, nil)
	return addr, auditLog
}

// startServerWith starts a server with cfg changed by edit; stop shuts it
// down (it is also shut down when the test ends).
func startServerWith(t *testing.T, edit func(*Config)) (addr string, auditLog *syncBuf, stop func()) {
	t.Helper()
	auditLog = &syncBuf{}
	cfg := Config{
		Addr:        "127.0.0.1:0",
		HostKeyDir:  hostKeyDir(t),
		Hostname:    "ipcam",
		Kernel:      "4.9.37",
		Version:     "dropbear_2019.78",
		MaxSessions: 4,
		Audit:       audit.New(auditLog),
	}
	if edit != nil {
		edit(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		})
	}
	t.Cleanup(stop)
	return l.Addr().String(), auditLog, stop
}

var (
	keyDirOnce sync.Once
	keyDir     string
)

// hostKeyDir is shared by all tests: generating an RSA key is slow.
func hostKeyDir(t *testing.T) string {
	keyDirOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ssham-keys")
		if err != nil {
			t.Fatal(err)
		}
		keyDir = dir
	})
	return keyDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if keyDir != "" {
		os.RemoveAll(keyDir)
	}
	os.Exit(code)
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
	c := dial(t, addr, "root", "xc3511")
	if v := string(c.ServerVersion()); v != "SSH-2.0-dropbear_2019.78" {
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
	want := "Linux ipcam 4.9.37 #1 Fri Mar 12 10:58:47 CST 2021 armv7l GNU/Linux"
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
	for _, w := range []string{`"msg":"auth"`, `"password":"xc3511"`, `"user":"root"`, `"line":"uname -a; whoami;`} {
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

func TestLoginPolicy(t *testing.T) {
	addr, log := startServer(t)
	_, priv, _ := ed25519Key()
	signer, _ := gossh.NewSignerFromKey(priv)
	try := func(user string, auth gossh.AuthMethod) error {
		c, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
			User:            user,
			Auth:            []gossh.AuthMethod{auth},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		})
		if err == nil {
			c.Close()
		}
		return err
	}
	tests := []struct {
		user string
		auth gossh.AuthMethod
		ok   bool
	}{
		{"root", gossh.Password("vizxv"), true},
		{"root", gossh.Password("xc3511"), false}, // root's password is vizxv now
		{"root", gossh.Password("vizxv"), true},
		{"admin", gossh.Password("admin"), true},
		{"root", gossh.Password("Zq8vLr2pXw"), false}, // a random string
		{"zzqqx", gossh.Password("admin"), false},     // not in /etc/passwd
		{"daemon", gossh.Password("admin"), false},    // no login shell
		{"root", gossh.PublicKeys(signer), false},     // no authorized_keys
	}
	for _, tt := range tests {
		if err := try(tt.user, tt.auth); (err == nil) != tt.ok {
			t.Errorf("%s: login ok = %v, want %v (%v)", tt.user, err == nil, tt.ok, err)
		}
	}
	logs := log.String()
	for _, w := range []string{`"success":false,"password":"Zq8vLr2pXw"`, `"method":"publickey"`, `"fingerprint":"` + gossh.FingerprintSHA256(signer.PublicKey()) + `"`, `"key":"ssh-ed25519 `} {
		if !strings.Contains(logs, w) {
			t.Errorf("audit log missing %s\n%s", w, logs)
		}
	}
}

func TestShadowMatchesLoginPassword(t *testing.T) {
	addr, _ := startServer(t)
	c := dial(t, addr, "admin", "hi3518")
	sess, _ := c.NewSession()
	out, err := sess.Output("whoami; echo $USER; grep ^admin: /etc/shadow | cut -d: -f2")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 || lines[0] != "root" || lines[1] != "admin" {
		t.Fatalf("got %q", out)
	}
	hash := lines[2]
	if salt := strings.Split(hash, "$"); len(salt) != 4 || crypt.MD5("hi3518", salt[2]) != hash {
		t.Errorf("admin's hash %q is not md5-crypt of the login password", hash)
	}
}

// TestHandshakeLooksLikeDropbear checks what a scanner sees before login.
func TestHandshakeLooksLikeDropbear(t *testing.T) {
	addr, _ := startServer(t)
	for _, algo := range []string{gossh.KeyAlgoECDSA256, gossh.KeyAlgoRSA} {
		var got gossh.PublicKey
		_, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
			User:              "root",
			Auth:              []gossh.AuthMethod{gossh.Password("x")},
			HostKeyAlgorithms: []string{algo},
			HostKeyCallback: func(_ string, _ net.Addr, k gossh.PublicKey) error {
				got = k
				return nil
			},
			Config: gossh.Config{
				Ciphers: []string{"aes128-ctr"},
				MACs:    []string{"hmac-sha1"},
			},
			Timeout: 5 * time.Second,
		})
		if got == nil {
			t.Errorf("host key %s not offered: %v", algo, err)
		}
	}
	// No ed25519 host key, no modern ciphers: dropbear 2019.78 has neither.
	for _, cfg := range []gossh.ClientConfig{
		{HostKeyAlgorithms: []string{gossh.KeyAlgoED25519}},
		{Config: gossh.Config{Ciphers: []string{"chacha20-poly1305@openssh.com"}}},
		{Config: gossh.Config{MACs: []string{"hmac-sha2-256-etm@openssh.com"}}},
		{Config: gossh.Config{KeyExchanges: []string{"mlkem768x25519-sha256"}}},
	} {
		cfg.User = "root"
		cfg.HostKeyCallback = gossh.InsecureIgnoreHostKey()
		cfg.Timeout = 5 * time.Second
		if _, err := gossh.Dial("tcp", addr, &cfg); err == nil || !strings.Contains(err.Error(), "no common algorithm") {
			t.Errorf("%+v: handshake succeeded or failed oddly: %v", cfg.Config, err)
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

	waitFor(t, out, "BusyBox v1.31.1 (2021-03-12 11:24:03 CST) built-in shell (ash)")
	waitFor(t, out, "~ #")

	io.WriteString(stdin, "echo $((6*7))\r")
	waitFor(t, out, "\n42")

	// Tab completion of a command name.
	io.WriteString(stdin, "whoa\t\r")
	waitFor(t, out, "# whoami")
	waitFor(t, out, "\nroot")

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
	for _, w := range []string{`"line":"echo $((6*7))"`, `"line":"whoami "`, `"msg":"session_end"`} {
		if !strings.Contains(log.String(), w) {
			t.Errorf("audit log missing %s", w)
		}
	}
}

func TestExecLooksLikeShC(t *testing.T) {
	addr, _ := startServer(t)
	c := dial(t, addr, "root", "xc3511")

	// stdout and stderr are separate streams.
	sess, _ := c.NewSession()
	var stdout, stderr syncBuf
	sess.Stdout, sess.Stderr = &stdout, &stderr
	_ = sess.Run(`echo "$0 [$-] $PATH $LD_LIBRARY_PATH"; ls /nope; sleep 1 & echo bg`)
	if got := stdout.String(); got != "sh [] /usr/sbin:/usr/bin:/sbin:/bin \nbg\n" {
		t.Errorf("stdout = %q", got)
	}
	if got := stderr.String(); got != "ls: /nope: No such file or directory\n" {
		t.Errorf("stderr = %q", got)
	}

	// Output arrives while the command runs.
	sess, _ = c.NewSession()
	var out syncBuf
	sess.Stdout = &out
	if err := sess.Start("echo first; sleep 2; echo second"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "first")
	if strings.Contains(out.String(), "second") {
		t.Error("output was buffered until the command finished")
	}
	_ = sess.Wait()

	// Channels on one connection share the disk.
	sess, _ = c.NewSession()
	_ = sess.Run("echo hi > /tmp/shared")
	sess, _ = c.NewSession()
	if b, err := sess.Output("cat /tmp/shared"); string(b) != "hi\n" {
		t.Errorf("second channel: %q, %v", b, err)
	}
}

func TestForwardingNeverConnects(t *testing.T) {
	addr, log := startServer(t)
	c := dial(t, addr, "root", "xc3511")

	// ssh -L to the camera itself: refused, with dropbear's empty reason.
	if _, err := c.Dial("tcp", "127.0.0.1:80"); err == nil || !strings.Contains(err.Error(), "connect failed") {
		t.Errorf("direct-tcpip: %v", err)
	}
	// ssh -R: accepted, and nothing ever arrives.
	l, err := c.Listen("tcp", "127.0.0.1:9000")
	if err != nil {
		t.Fatalf("tcpip-forward: %v", err)
	}
	l.Close()

	// sftp: dropbear runs sftp-server through the shell; there is none.
	sess, _ := c.NewSession()
	stderr, _ := sess.StderrPipe()
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(stderr); string(b) != "sh: /usr/libexec/sftp-server: not found\n" {
		t.Errorf("sftp: %q", b)
	}
	c.Close()

	waitFor(t, log, `"msg":"disconnect"`)
	logs := log.String()
	for _, w := range []string{`"kind":"direct-tcpip","dest":"127.0.0.1:80"`, `"kind":"tcpip-forward","bind":"127.0.0.1:9000"`, `"mode":"sftp"`} {
		if !strings.Contains(logs, w) {
			t.Errorf("audit log missing %s\n%s", w, logs)
		}
	}
}

// run runs cmd in a new exec channel on c.
func run(t *testing.T, c *gossh.Client, cmd string) string {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.CombinedOutput(cmd)
	return string(out)
}

func TestSessionsShareTheCamera(t *testing.T) {
	addr, _ := startServer(t)
	a := dial(t, addr, "root", "xc3511")
	b := dial(t, addr, "admin", "admin")

	run(t, a, "echo dropped > /tmp/.x")
	if out := run(t, b, "cat /tmp/.x"); out != "dropped\n" {
		t.Errorf("b sees %q", out)
	}
	// a's login shell, waiting in an interactive session, shows in b's ps.
	sess, _ := a.NewSession()
	if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var ps string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(ps, " -sh") {
		ps = run(t, b, "ps")
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(ps, " -sh") || !strings.Contains(ps, "sh -c ps") {
		t.Fatalf("ps:\n%s", ps)
	}

	// Killing a's shell from b ends a's connection.
	var pid string
	for _, l := range strings.Split(ps, "\n") {
		if strings.HasSuffix(l, " -sh") {
			pid = strings.Fields(l)[0]
		}
	}
	run(t, b, "kill -9 "+pid)
	if err := sess.Wait(); err == nil {
		t.Error("a's session survived kill -9 of its shell")
	}
}

func TestReboot(t *testing.T) {
	addr, log, _ := startServerWith(t, func(c *Config) { c.RebootDowntime = 500 * time.Millisecond })
	c := dial(t, addr, "root", "xc3511")
	run(t, c, "echo ram > /tmp/r; echo flash > /mnt/mtd/f")
	sess, _ := c.NewSession()
	_ = sess.Run("reboot")
	if _, err := c.NewSession(); err == nil {
		t.Error("connection survived reboot")
	}
	// Down for a while, then back with a fresh uptime and RAM disk.
	if _, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{User: "root", Auth: []gossh.AuthMethod{gossh.Password("xc3511")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}); err == nil {
		t.Error("login during reboot")
	}
	time.Sleep(600 * time.Millisecond)
	c = dial(t, addr, "root", "xc3511")
	out := run(t, c, "cat /tmp/r /mnt/mtd/f; cut -d. -f1 /proc/uptime")
	if !strings.Contains(out, "No such file") || !strings.Contains(out, "flash\n") || !strings.HasSuffix(out, "\n0\n") {
		t.Errorf("after reboot:\n%s", out)
	}
	if !strings.Contains(log.String(), `"msg":"reboot"`) {
		t.Error("reboot not logged")
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.gob")
	edit := func(c *Config) { c.StatePath = state }
	addr, _, stop := startServerWith(t, edit)
	c := dial(t, addr, "root", "xc3511")
	before := run(t, c, "echo kept > /tmp/k; echo $$; cut -d' ' -f1 /proc/uptime")
	c.Close()
	stop()

	addr, _, _ = startServerWith(t, edit)
	c = dial(t, addr, "root", "xc3511")
	after := run(t, c, "cat /tmp/k; echo $$; cut -d' ' -f1 /proc/uptime")
	b, a := strings.Fields(before), strings.Fields(after)
	if len(a) != 3 || a[0] != "kept" {
		t.Fatalf("after restart: %q", after)
	}
	pidBefore, _ := strconv.Atoi(b[0])
	pidAfter, _ := strconv.Atoi(a[1])
	upBefore, _ := strconv.ParseFloat(b[1], 64)
	upAfter, _ := strconv.ParseFloat(a[2], 64)
	if pidAfter <= pidBefore || upAfter < upBefore {
		t.Errorf("pid %d -> %d, uptime %v -> %v", pidBefore, pidAfter, upBefore, upAfter)
	}
}

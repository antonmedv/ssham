// Package server wires the fake shell into a Wish SSH server.
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"charm.land/ssh"
	"charm.land/wish/v2"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/commands"
	"github.com/antonmedv/ssham/internal/crypt"
	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/shell"
	"github.com/antonmedv/ssham/internal/tui"
	"github.com/antonmedv/ssham/internal/vfs"
)

// Config configures the honeypot.
type Config struct {
	Addr        string
	HostKeyDir  string // where the host keys are kept, generated if missing
	Hostname    string
	Kernel      string
	Version     string // SSH server version string, without "SSH-2.0-"
	MaxSessions int
	// StatePath, if set, is where the camera's files, uptime and pids are
	// kept across restarts.
	StatePath string
	// RebootDowntime is how long reboot keeps the camera offline.
	RebootDowntime time.Duration
	IdleTimeout    time.Duration
	MaxTimeout     time.Duration
	Audit          *audit.Logger
	Log            *slog.Logger
}

// Server is the honeypot.
type Server struct {
	cfg    Config
	dev    *device
	stop   chan struct{}
	active atomic.Int64
	ssh    *ssh.Server
}

type ctxKey string

const (
	sessionIDKey ctxKey = "ssham-session-id"
	fsKey        ctxKey = "ssham-fs"
)

// New builds a server. Call ListenAndServe to start it.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	booted := time.Now().Add(-time.Duration(30+randInt(60))*24*time.Hour - time.Duration(randInt(86400))*time.Second)
	keys, err := loadHostKeys(cfg.HostKeyDir)
	if err != nil {
		return nil, err
	}
	host := rootfs.Host{Hostname: cfg.Hostname, Kernel: cfg.Kernel, Booted: booted, Files: map[string][]byte{}}
	host.Identify(keys[0].signer.PublicKey().Marshal())
	for _, k := range keys {
		host.Files[k.path] = k.dropbear
	}
	if cfg.RebootDowntime <= 0 {
		cfg.RebootDowntime = 45 * time.Second
	}
	dev, err := newDevice(host, cfg.StatePath, cfg.RebootDowntime)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, dev: dev, stop: make(chan struct{})}

	srv, err := wish.NewServer(
		wish.WithAddress(cfg.Addr),
		func(srv *ssh.Server) error {
			for _, k := range keys {
				srv.AddHostKey(k.signer)
			}
			srv.ServerConfigCallback = serverConfig
			srv.ChannelHandlers = map[string]ssh.ChannelHandler{
				"session":      ssh.DefaultSessionHandler,
				"direct-tcpip": s.directTCPIP,
			}
			srv.RequestHandlers = map[string]ssh.RequestHandler{
				"tcpip-forward":        s.tcpipForward,
				"cancel-tcpip-forward": s.tcpipForward,
			}
			srv.SubsystemHandlers = map[string]ssh.SubsystemHandler{"sftp": s.sftp}
			return nil
		},
		wish.WithVersion(cfg.Version),
		wish.WithPasswordAuth(s.passwordAuth),
		wish.WithPublicKeyAuth(s.publicKeyAuth),
		wish.WithIdleTimeout(cfg.IdleTimeout),
		wish.WithMaxTimeout(cfg.MaxTimeout),
		wish.WithMiddleware(s.middleware),
	)
	if err != nil {
		return nil, err
	}
	srv.ConnCallback = func(ctx ssh.Context, conn net.Conn) net.Conn {
		id := sessionID(ctx)
		if !s.dev.up(time.Now()) {
			cfg.Audit.Event(audit.SessionRejected, "session", id, "remote", conn.RemoteAddr().String(), "reason", "rebooting")
			return nil // the camera is rebooting
		}
		cfg.Audit.Event(audit.Connect, "session", id, "remote", conn.RemoteAddr().String())
		return &loggedConn{Conn: conn, start: time.Now(), done: func(d time.Duration) {
			cfg.Audit.Event(audit.Disconnect, "session", id, "remote", conn.RemoteAddr().String(), "duration_s", d.Seconds())
		}}
	}
	s.ssh = srv
	return s, nil
}

// ListenAndServe starts accepting connections.
func (s *Server) ListenAndServe() error {
	go s.saveLoop()
	return s.ssh.ListenAndServe()
}

// Serve accepts connections on l.
func (s *Server) Serve(l net.Listener) error {
	go s.saveLoop()
	return s.ssh.Serve(l)
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.stop)
	err := s.ssh.Shutdown(ctx)
	if serr := s.dev.save(); serr != nil {
		s.cfg.Log.Error("save state", "err", serr)
	}
	return err
}

// saveLoop saves the device's state now and then, in case ssham dies.
func (s *Server) saveLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			if err := s.dev.save(); err != nil {
				s.cfg.Log.Error("save state", "err", err)
			}
		}
	}
}

func randInt(n int) int {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24) % n
}

func randomSalt() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = crypt.SaltChars[randInt(len(crypt.SaltChars))]
	}
	return string(b)
}

func newSessionID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sessionID returns a stable ID for the connection, shared by the auth
// events and the session events.
func sessionID(ctx ssh.Context) string {
	ctx.Lock()
	defer ctx.Unlock()
	if id, ok := ctx.Value(sessionIDKey).(string); ok {
		return id
	}
	id := newSessionID()
	ctx.SetValue(sessionIDKey, id)
	return id
}

func (s *Server) authEvent(ctx ssh.Context, method string, success bool, attrs ...any) {
	base := []any{
		"session", sessionID(ctx),
		"remote", ctx.RemoteAddr().String(),
		"user", ctx.User(),
		"client_version", ctx.ClientVersion(),
		"method", method,
		"success", success,
	}
	s.cfg.Audit.Event(audit.Auth, append(base, attrs...)...)
}

var validUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// sanitizeUser maps the login name to something safe to show in a prompt
// and use as a path component.
func sanitizeUser(u string) string {
	u = strings.ToLower(u)
	if validUser.MatchString(u) {
		return u
	}
	return "admin"
}

func (s *Server) middleware(next ssh.Handler) ssh.Handler {
	return func(sess ssh.Session) {
		defer next(sess)
		ctx := sess.Context()
		id := sessionID(ctx)
		slog := s.cfg.Audit.Session(id, sess.RemoteAddr().String())

		if n := s.active.Add(1); n > int64(s.cfg.MaxSessions) {
			s.active.Add(-1)
			slog.Event(audit.SessionRejected, "reason", "max sessions")
			_ = sess.Exit(1)
			return
		}
		defer s.active.Add(-1)

		pty, winCh, isPty := sess.Pty()
		start := time.Now()
		slog.Event(audit.SessionStart,
			"user", sess.User(),
			"client_version", sess.Context().ClientVersion(),
			"pty", isPty,
			"term", pty.Term,
			"width", pty.Window.Width,
			"height", pty.Window.Height,
			"command", sess.RawCommand(),
			"env", sess.Environ(),
		)

		// The session runs on the camera's shared disk and process table.
		// Killing its shell from another session, or a reboot, hangs up
		// the whole connection.
		hangup := func() {
			if c, ok := ctx.Value(ssh.ContextKeyConn).(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
		host, devFS, kernel, done := s.dev.session(hangup)
		defer done()
		s.setPassword(ctx, devFS, sess.User())
		clientIP, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
		clientPort, _ := strconv.Atoi(port)
		cfg := shell.Config{
			Host:       host,
			Kernel:     kernel,
			Hangup:     hangup,
			Reboot:     func() { s.dev.reboot(time.Now()) },
			User:       sanitizeUser(sess.User()),
			FS:         devFS,
			Commands:   commands.Registry(),
			Log:        slog,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			Started:    start,
		}

		if ssh.AgentRequested(sess) {
			// ssh -A: dropbear makes a socket and points SSH_AUTH_SOCK at
			// it. Nothing listens on it here.
			dir := fmt.Sprintf("/tmp/dropbear-%08x%08x", randInt(1<<30), randInt(1<<30))
			cfg.Env = map[string]string{"SSH_AUTH_SOCK": fmt.Sprintf("%s/auth-%08x-0", dir, randInt(1<<30))}
			_ = cfg.FS.Mkdir("root", dir, true)
			_ = cfg.FS.Chmod("root", dir, 0o700)
			slog.Event(audit.Forward, "kind", "agent")
		}
		var code int
		switch {
		case sess.RawCommand() != "":
			cfg.Mode = shell.RunCommand
			code = s.runExec(ctx, sess, cfg, slog)
		case isPty:
			cfg.Term = pty.Term
			if cfg.Term == "" {
				cfg.Term = "xterm"
			}
			code = s.runInteractive(ctx, sess, cfg, pty, winCh, slog)
		default:
			cfg.Mode = shell.PipedShell
			code = s.runPiped(ctx, sess, cfg)
		}
		slog.Event(audit.SessionEnd, "exit_code", code, "duration_s", time.Since(start).Seconds())
		_ = sess.Exit(code)
	}
}

// runExec handles `ssh host 'command'`. Output is sent as it is
// written, stderr on its own stream, as dropbear does. With a pty (ssh -t)
// both go to the terminal, with newlines translated.
func (s *Server) runExec(ctx context.Context, sess ssh.Session, cfg shell.Config, slog *audit.SessionLogger) int {
	slog.Event(audit.Input, "line", sess.RawCommand(), "mode", "exec")
	sh := shell.New(cfg, &plainTerm{w: sess, r: bufio.NewReader(sess)})
	defer sh.Close()
	budget := &outputBudget{left: maxExecOutput}
	var stdout, stderr io.Writer = budget.wrap(sess), budget.wrap(sess.Stderr())
	if _, _, isPty := sess.Pty(); isPty {
		stdout = budget.wrap(crlfWriter{sess})
		stderr = stdout
	}
	return sh.Command(ctx, sess.RawCommand(), io.LimitReader(sess, 1<<20), stdout, stderr)
}

// maxExecOutput caps what one exec request can send.
const maxExecOutput = 8 << 20

// outputBudget drops output past a total size shared by several writers.
type outputBudget struct {
	mu   sync.Mutex
	left int
}

func (b *outputBudget) wrap(w io.Writer) io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		b.mu.Lock()
		n := min(len(p), b.left)
		b.left -= n
		b.mu.Unlock()
		if n > 0 {
			if _, err := w.Write(p[:n]); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// crlfWriter turns \n into \r\n, as a pty's output processing does.
type crlfWriter struct{ w io.Writer }

func (c crlfWriter) Write(p []byte) (int, error) {
	if _, err := c.w.Write(bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n"))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// setPassword makes the hash in /etc/shadow the password this connection
// logged in with, so cracking it gives back the same password.
func (s *Server) setPassword(ctx ssh.Context, f *vfs.FS, user string) {
	ctx.Lock()
	defer ctx.Unlock()
	pw, ok := ctx.Value(passwordKey).(string)
	if !ok || ctx.Value(fsKey) != nil {
		return
	}
	ctx.SetValue(fsKey, true)
	_ = rootfs.SetPassword(f, user, crypt.MD5(pw, randomSalt()), time.Time{})
}

// runPiped handles sessions with no pty and no command, e.g. a script
// piped into `ssh host`. Lines are executed as bash would with no prompt.
func (s *Server) runPiped(ctx context.Context, sess ssh.Session, cfg shell.Config) int {
	sh := shell.New(cfg, &plainTerm{w: sess, r: bufio.NewReader(io.LimitReader(sess, 1<<20))})
	defer sh.Close()
	return sh.Run(ctx)
}

// runInteractive serves an interactive shell on a pty, edited the way
// BusyBox ash's lineedit would.
func (s *Server) runInteractive(parent context.Context, sess ssh.Session, cfg shell.Config, pty ssh.Pty, winCh <-chan ssh.Window, slog *audit.SessionLogger) int {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	term := tui.New(sess, pty.Window.Width, slog)
	sh := shell.New(cfg, term)
	defer sh.Close()
	term.Attach(sh)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case w, ok := <-winCh:
				if !ok {
					return
				}
				term.SetWidth(w.Width)
			}
		}
	}()
	go term.Run(ctx, sess)

	code := 0
	func() {
		defer func() {
			if r := recover(); r != nil {
				s.cfg.Log.Error("shell panic", "panic", r)
				code = 139
			}
		}()
		_, _ = io.WriteString(term, sh.Motd())
		code = sh.Run(ctx)
	}()
	return code
}

// plainTerm is a Terminal for sessions without a pty.
type plainTerm struct {
	w io.Writer
	r *bufio.Reader
}

func (t *plainTerm) Write(p []byte) (int, error) { return t.w.Write(p) }

func (t *plainTerm) ReadLine(prompt string, echo bool) (string, error) {
	if !echo && prompt != "" {
		// sudo and friends print their prompt even without a tty.
		fmt.Fprint(t.w, prompt)
	}
	line, err := t.r.ReadString('\n')
	if err != nil && line == "" {
		return "", io.EOF
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// loggedConn logs when the connection closes.
type loggedConn struct {
	net.Conn
	start time.Time
	once  sync.Once
	done  func(time.Duration)
}

func (c *loggedConn) Close() error {
	c.once.Do(func() { c.done(time.Since(c.start)) })
	return c.Conn.Close()
}

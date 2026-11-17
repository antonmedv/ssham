// Package server wires the fake shell into a Wish SSH server.
package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/ssh"
	"charm.land/wish/v2"
	"charm.land/wish/v2/bubbletea"
	gossh "golang.org/x/crypto/ssh"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
	"github.com/antonmedv/ssham/internal/tui"
	"github.com/antonmedv/ssham/internal/vfs"
)

// Config configures the honeypot.
type Config struct {
	Addr        string
	HostKeyPath string
	Hostname    string
	Kernel      string
	Version     string // SSH server version string, without "SSH-2.0-"
	MaxSessions int
	IdleTimeout time.Duration
	MaxTimeout  time.Duration
	Audit       *audit.Logger
	Log         *slog.Logger
}

// Server is the honeypot.
type Server struct {
	cfg    Config
	base   *vfs.FS
	host   vfs.Host
	active atomic.Int64
	ssh    *ssh.Server
}

type ctxKey string

const sessionIDKey ctxKey = "ssham-session-id"

// New builds a server. Call ListenAndServe to start it.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	booted := time.Now().Add(-time.Duration(30+randInt(60))*24*time.Hour - time.Duration(randInt(86400))*time.Second)
	host := vfs.Host{Hostname: cfg.Hostname, Kernel: cfg.Kernel, Booted: booted}
	s := &Server{cfg: cfg, host: host, base: vfs.NewBase(host)}

	srv, err := wish.NewServer(
		wish.WithAddress(cfg.Addr),
		wish.WithHostKeyPath(cfg.HostKeyPath),
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
		cfg.Audit.Event("connect", "remote", conn.RemoteAddr().String())
		return conn
	}
	s.ssh = srv
	return s, nil
}

// ListenAndServe starts accepting connections.
func (s *Server) ListenAndServe() error { return s.ssh.ListenAndServe() }

// Serve accepts connections on l.
func (s *Server) Serve(l net.Listener) error { return s.ssh.Serve(l) }

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error { return s.ssh.Shutdown(ctx) }

func randInt(n int) int {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24) % n
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
	s.cfg.Audit.Event("auth", append(base, attrs...)...)
}

func (s *Server) passwordAuth(ctx ssh.Context, password string) bool {
	s.authEvent(ctx, "password", true, "password", password)
	return true
}

func (s *Server) publicKeyAuth(ctx ssh.Context, key ssh.PublicKey) bool {
	s.authEvent(ctx, "publickey", true,
		"key_type", key.Type(),
		"fingerprint", gossh.FingerprintSHA256(key),
		"key", strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key))))
	return true
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
			slog.Event("session_rejected", "reason", "max sessions")
			_ = sess.Exit(1)
			return
		}
		defer s.active.Add(-1)

		pty, winCh, isPty := sess.Pty()
		start := time.Now()
		slog.Event("session_start",
			"user", sess.User(),
			"client_version", sess.Context().ClientVersion(),
			"pty", isPty,
			"term", pty.Term,
			"width", pty.Window.Width,
			"height", pty.Window.Height,
			"command", sess.RawCommand(),
			"env", sess.Environ(),
		)

		clientIP, _, _ := net.SplitHostPort(sess.RemoteAddr().String())
		cfg := shell.Config{
			Host:     s.host,
			User:     sanitizeUser(sess.User()),
			FS:       s.base.Clone(),
			Log:      slog,
			ClientIP: clientIP,
			Started:  start,
		}

		var code int
		switch {
		case sess.RawCommand() != "":
			code = s.runExec(ctx, sess, cfg, slog)
		case isPty:
			cfg.Term = pty.Term
			if cfg.Term == "" {
				cfg.Term = "xterm"
			}
			code = s.runInteractive(ctx, sess, cfg, pty, winCh, slog)
		default:
			code = s.runPiped(ctx, sess, cfg)
		}
		slog.Event("session_end", "exit_code", code, "duration_s", time.Since(start).Seconds())
		_ = sess.Exit(code)
	}
}

// runExec handles `ssh host 'command'`.
func (s *Server) runExec(ctx context.Context, sess ssh.Session, cfg shell.Config, slog *audit.SessionLogger) int {
	slog.Event("input", "line", sess.RawCommand(), "mode", "exec")
	sh := shell.New(cfg, &plainTerm{w: sess, r: bufio.NewReader(sess)})
	out, code := sh.Capture(ctx, sess.RawCommand(), io.LimitReader(sess, 1<<20))
	if _, _, isPty := sess.Pty(); isPty {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	_, _ = io.WriteString(sess, out)
	return code
}

// runPiped handles sessions with no pty and no command, e.g. a script
// piped into `ssh host`. Lines are executed as bash would with no prompt.
func (s *Server) runPiped(ctx context.Context, sess ssh.Session, cfg shell.Config) int {
	sh := shell.New(cfg, &plainTerm{w: sess, r: bufio.NewReader(io.LimitReader(sess, 1<<20))})
	return sh.Run(ctx)
}

// runInteractive serves a full interactive shell through Bubble Tea.
func (s *Server) runInteractive(parent context.Context, sess ssh.Session, cfg shell.Config, pty ssh.Pty, winCh <-chan ssh.Window, slog *audit.SessionLogger) int {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	width, height := pty.Window.Width, pty.Window.Height
	if width <= 0 || height <= 0 {
		width, height = 80, 24
	}
	// SSH_TTY in the environment stops Bubble Tea from querying terminal
	// capabilities, which bash would never do.
	env := []string{"TERM=" + cfg.Term, "SSH_TTY=/dev/pts/0"}
	for _, kv := range sess.Environ() {
		if !strings.HasPrefix(kv, "WT_SESSION=") && !strings.HasPrefix(kv, "TERM=") {
			env = append(env, kv)
		}
	}
	opts := append(bubbletea.MakeOptions(sess),
		tea.WithOutput(filterWriter{w: sess}),
		tea.WithEnvironment(env),
		tea.WithWindowSize(width, height),
	)

	term := tui.NewTerm(ctx, width)
	sh := shell.New(cfg, term)
	model := tui.NewModel(term, sh, slog, width)
	prog := tea.NewProgram(model, opts...)
	term.Attach(prog)

	go func() {
		for {
			select {
			case <-ctx.Done():
				prog.Quit()
				return
			case w := <-winCh:
				prog.Send(tea.WindowSizeMsg{Width: w.Width, Height: w.Height})
			}
		}
	}()

	shellDone := make(chan int, 1)
	go func() {
		code := 0
		defer func() {
			if r := recover(); r != nil {
				s.cfg.Log.Error("shell panic", "panic", r)
				code = 139
			}
			term.Done()
			shellDone <- code
		}()
		_, _ = io.WriteString(term, sh.Motd())
		code = sh.Run(ctx)
	}()

	if _, err := prog.Run(); err != nil && !errors.Is(err, tea.ErrProgramKilled) {
		s.cfg.Log.Debug("program exited", "err", err)
	}
	cancel()
	prog.Kill()

	select {
	case code := <-shellDone:
		return code
	case <-time.After(2 * time.Second):
		return 0
	}
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

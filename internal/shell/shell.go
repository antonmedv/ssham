// Package shell implements a fake bash. It parses and runs command lines,
// but every program is simulated in Go (see the commands package) against an
// in-memory filesystem; nothing is ever executed on the host.
package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/vfs"
)

// ErrInterrupt is returned by Terminal.ReadLine when the user presses Ctrl+C.
var ErrInterrupt = errors.New("interrupt")

// Terminal is the shell's connection to the attacker.
type Terminal interface {
	io.Writer
	// ReadLine shows prompt and reads one line of input. If echo is false
	// the input is hidden (for passwords). It returns io.EOF on Ctrl+D at
	// an empty line and ErrInterrupt on Ctrl+C.
	ReadLine(prompt string, echo bool) (string, error)
}

// Config describes the fake host and the session.
type Config struct {
	Host     rootfs.Host
	User     string
	FS       *vfs.FS // the session's private filesystem
	Commands *Registry
	Log      *audit.SessionLogger
	Term     string // $TERM, empty if no pty
	ClientIP string
	Started  time.Time

	// Clock, Rand and Sleep make sessions deterministic in tests. When nil,
	// real time, real randomness and real sleeping are used.
	Clock func() time.Time
	Rand  *rand.Rand
	Sleep func(ctx context.Context, d time.Duration) bool
}

// Resource limits.
const (
	maxCaptureBytes = 1 << 20  // per pipe stage, $(...) and redirection
	maxDepth        = 8        // nested scripts and command substitutions
	maxLineLen      = 64 << 10 // one command line
	maxHistory      = 1000
)

// Shell is one fake bash session.
type Shell struct {
	cfg  Config
	fs   *vfs.FS
	term Terminal
	log  *audit.SessionLogger

	user  User
	cwd   string
	stack []identity // previous identities, for su, sudo -i and nested shells

	vars    map[string]string
	exports map[string]bool
	aliases map[string]string
	history []string
	args    []string // $0 $1 ... while running a script
	status  int      // $?
	pid     int      // $$
	nextPID int
	jobs    int

	sudoCached bool // sudo asked for a password already
	depth      int  // script / command substitution nesting
	leaving    bool // exit was called in a nested script: unwind it
	exited     bool
	exitCode   int

	mu     sync.Mutex
	cancel context.CancelFunc // interrupts the running command
}

// New creates a shell for one session, adding the login user to the
// filesystem if needed.
func New(cfg Config, term Terminal) *Shell {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	if cfg.Commands == nil {
		cfg.Commands = NewRegistry()
	}
	if cfg.Started.IsZero() {
		cfg.Started = cfg.Clock()
	}
	cfg.FS.Now = cfg.Clock

	uid := 1001
	switch cfg.User {
	case "root":
		uid = 0
	case "ubuntu":
		uid = 1000
	}
	rootfs.AddUser(cfg.FS, cfg.User, uid)
	user, _ := lookupUser(cfg.FS, cfg.User)

	r := cfg.Rand
	s := &Shell{
		cfg:     cfg,
		fs:      cfg.FS,
		term:    term,
		log:     cfg.Log,
		user:    user,
		cwd:     user.Home,
		vars:    map[string]string{},
		exports: map[string]bool{},
		aliases: map[string]string{"ls": "ls --color=auto", "grep": "grep --color=auto", "ll": "ls -alF", "la": "ls -A", "l": "ls -CF"},
		pid:     2000 + r.IntN(30000),
	}
	s.nextPID = s.pid + 1
	env := [][2]string{
		{"SHELL", "/bin/bash"},
		{"LANG", "C.UTF-8"},
		{"USER", user.Name},
		{"LOGNAME", user.Name},
		{"HOME", user.Home},
		{"PWD", s.cwd},
		{"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"},
		{"SSH_CONNECTION", fmt.Sprintf("%s %d 10.0.2.15 22", cfg.ClientIP, 40000+r.IntN(20000))},
		{"SSH_CLIENT", fmt.Sprintf("%s %d 22", cfg.ClientIP, 40000+r.IntN(20000))},
		{"MOTD_SHOWN", "pam"},
		{"XDG_SESSION_ID", fmt.Sprint(r.IntN(400) + 1)},
		{"XDG_RUNTIME_DIR", fmt.Sprintf("/run/user/%d", user.UID)},
		{"SHLVL", "1"},
	}
	if cfg.Term != "" {
		env = append(env, [2]string{"TERM", cfg.Term}, [2]string{"SSH_TTY", "/dev/pts/0"})
	}
	for _, kv := range env {
		s.vars[kv[0]] = kv[1]
		s.exports[kv[0]] = true
	}
	return s
}

// ExitCode is the status the session should exit with.
func (s *Shell) ExitCode() int { return s.exitCode }

// Interrupt cancels the command that is currently running, if any.
func (s *Shell) Interrupt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// view is the filesystem as the current user sees it.
func (s *Shell) view() *vfs.View { return s.fs.As(s.user.Name, s.cwd) }

func (s *Shell) resolve(p string) string { return vfs.Abs(s.cwd, p) }

func (s *Shell) now() time.Time { return s.cfg.Clock() }

func (s *Shell) getVar(name string) string {
	switch name {
	case "RANDOM":
		return fmt.Sprint(s.cfg.Rand.IntN(32768))
	case "UID", "EUID":
		return fmt.Sprint(s.user.UID)
	case "HOSTNAME":
		return s.cfg.Host.Hostname
	case "BASH_VERSION":
		return "5.2.21(1)-release"
	case "PPID":
		return fmt.Sprint(s.pid - 1)
	case "SECONDS":
		return fmt.Sprint(int(s.now().Sub(s.cfg.Started).Seconds()))
	}
	return s.vars[name]
}

func (s *Shell) setVar(name, val string) { s.vars[name] = val }

// environ returns NAME=value pairs, sorted; exported variables only if
// exportedOnly.
func (s *Shell) environ(exportedOnly bool) []string {
	var out []string
	for k, v := range s.vars {
		if exportedOnly && !s.exports[k] {
			continue
		}
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func (s *Shell) allocPID() int {
	s.nextPID += 1 + s.cfg.Rand.IntN(7)
	return s.nextPID
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

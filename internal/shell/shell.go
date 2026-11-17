// Package shell implements a fake BusyBox ash. It parses and runs command
// lines, but every program is simulated in Go (see the commands package)
// against an in-memory filesystem; nothing is ever executed on the host.
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

	depth     int    // script / command substitution nesting
	loopDepth int    // nested loops, for break and continue
	jump      int    // pending break (> 0) or continue (< 0) levels
	expandErr string // an error found while expanding the current command
	leaving   bool   // exit was called in a nested script: unwind it
	exited    bool
	exitCode  int

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

	// The device only has the accounts in its /etc/passwd. Any other
	// login name gets a root shell, as on most such devices.
	user, ok := lookupUser(cfg.FS, cfg.User)
	if !ok {
		user, _ = lookupUser(cfg.FS, "root")
	}

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
		aliases: map[string]string{},
		pid:     2000 + r.IntN(30000),
	}
	s.nextPID = s.pid + 1
	// What dropbear passes to the login shell, plus what /etc/profile sets.
	env := [][2]string{
		{"USER", user.Name},
		{"LOGNAME", user.Name},
		{"HOME", user.Home},
		{"SHELL", user.Shell},
		{"PATH", "/bin:/sbin:/usr/bin:/usr/sbin"},
		{"LD_LIBRARY_PATH", "/lib:/usr/lib"},
		{"PWD", s.cwd},
		{"SSH_CLIENT", fmt.Sprintf("%s %d 22", cfg.ClientIP, 40000+r.IntN(20000))},
		{"SSH_CONNECTION", fmt.Sprintf("%s %d 192.168.1.108 22", cfg.ClientIP, 40000+r.IntN(20000))},
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
	if name == "PPID" {
		return fmt.Sprint(s.pid - 1)
	}
	return s.vars[name]
}

func (s *Shell) setVar(name, val string) { s.vars[name] = val }

// expandError records an error found during expansion, such as a bad
// substitution. The command is not run; see checkExpand.
func (s *Shell) expandError(msg string) {
	if s.expandErr == "" {
		s.expandErr = msg
	}
}

// checkExpand reports a pending expansion error. It returns false if the
// command must not run.
func (s *Shell) checkExpand(stderr io.Writer) bool {
	if s.expandErr == "" {
		return true
	}
	fmt.Fprintf(stderr, "sh: %s\n", s.expandErr)
	s.expandErr = ""
	return false
}

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

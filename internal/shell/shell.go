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
	"strconv"
	"sync"
	"sync/atomic"
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
	Host       rootfs.Host
	Mode       Mode
	User       string
	FS         *vfs.FS // the session's private filesystem
	Commands   *Registry
	Log        *audit.SessionLogger
	Term       string // $TERM, empty if no pty
	ClientIP   string
	ClientPort int
	// Kernel is the process table the session shares with others on the
	// camera. Nil gives the session one of its own.
	Kernel *rootfs.Kernel
	// Hangup ends the session from outside, when its shell or dropbear is
	// killed from another session.
	Hangup func()
	// Reboot reboots the camera, for reboot and friends.
	Reboot  func()
	Env     map[string]string // more variables dropbear sets
	Started time.Time

	// Clock, Rand and Sleep make sessions deterministic in tests. When nil,
	// real time, real randomness and real sleeping are used.
	Clock func() time.Time
	Rand  *rand.Rand
	Sleep func(ctx context.Context, d time.Duration) bool
}

// Mode is how dropbear started the shell.
type Mode int

const (
	// LoginShell is an interactive login shell on a pty: argv0 "-sh", $- "smi".
	LoginShell Mode = iota
	// PipedShell is a login shell reading commands from a pipe, as in
	// `ssh host < script`: "-sh", $- "s".
	PipedShell
	// RunCommand is `ssh host 'cmd'`: dropbear runs sh -c, which reads no
	// profile: "sh", $- empty.
	RunCommand
)

// Resource limits.
const (
	maxCaptureBytes = 1 << 20  // per pipe stage, $(...) and redirection
	maxDepth        = 64       // nested shells and function calls; deeper "overflows the stack"
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

	vars     map[string]string
	exports  map[string]bool
	aliases  map[string]string
	history  []string
	args     []string // $0 $1 ... while running a script
	status   int      // $?
	pid      int      // $$: the current shell process
	loginPID int      // the login shell
	procs    map[int]rootfs.Proc
	execPID  int // the process of the command being run, for Env
	lastBg   int // $!
	funcs    map[string]*command
	locals   []map[string]*string // saved values for local, per function call
	// funcDepth counts function calls; exiting is set when exit runs in
	// one, so the whole shell unwinds rather than just the function.
	funcDepth  int
	exiting    bool
	jobList    []*job
	ffwd       *time.Duration // set while a background job runs: sleeps add up here
	kernel     *rootfs.Kernel
	mine       map[int]bool // the pids this session started
	tty        string       // /dev/pts/N, if the session has a terminal
	pty        int
	signaled   atomic.Int32                      // a signal that ended the session
	pendingSig atomic.Int32                      // a trapped signal whose action is to run
	trapSnap   atomic.Pointer[map[string]string] // the traps, for kill from other sessions
	traps      map[string]string
	opts       map[byte]bool // set -e, -x, ...
	condDepth  int           // > 0 while running an if/while condition or a && || operand
	forks      int           // work done by the current command line; see maxForks
	steps      int
	aborted    bool
	crashed    bool            // the shell overflowed its stack; see overflow
	children   int             // nested child shells; see inChild
	runCtx     context.Context // of the command line being run
	lineno     int
	errOut     io.Writer // stderr of the command being run, for $(...)
	substRan   bool      // a $(...) ran while expanding the current command
	substCode  int       // and its exit status
	stagePID   int       // a pid a pipeline reserved for its next stage

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
	login, ok := lookupUser(cfg.FS, cfg.User)
	if !ok {
		login, _ = lookupUser(cfg.FS, "root")
	}
	// The kernel only knows the uid: admin (uid 0) is root to whoami, id
	// and ls, while dropbear sets USER and HOME from the login name.
	user := login
	if u, ok := lookupUID(cfg.FS, login.UID); ok {
		user = u
	}

	s := &Shell{
		cfg:     cfg,
		fs:      cfg.FS,
		term:    term,
		log:     cfg.Log,
		user:    user,
		cwd:     login.Home,
		vars:    map[string]string{},
		exports: map[string]bool{},
		aliases: map[string]string{},
		funcs:   map[string]*command{},
		traps:   map[string]string{},
		opts:    map[byte]bool{},
	}
	if cfg.Kernel == nil {
		s.cfg.Kernel = rootfs.NewKernel(cfg.Host.Booted, cfg.Clock())
	}
	s.kernel = s.cfg.Kernel
	s.mine = map[int]bool{}
	s.pid = s.kernel.AllocPID(0) + 1 // its dropbear child is the pid before
	s.loginPID = s.pid
	// ash's own variables.
	for k, v := range map[string]string{"IFS": " \t\n", "PS1": "\\w \\$ ", "PS2": "> ", "PS4": "+ ", "OPTIND": "1"} {
		s.vars[k] = v
	}
	s.startProcs()
	// What dropbear passes to the login shell, plus what /etc/profile sets.
	env := [][2]string{
		{"USER", login.Name},
		{"LOGNAME", login.Name},
		{"HOME", login.Home},
		{"SHELL", login.Shell},
		{"PWD", s.cwd},
		{"SSH_CLIENT", fmt.Sprintf("%s %d 22", cfg.ClientIP, cfg.ClientPort)},
		{"SSH_CONNECTION", fmt.Sprintf("%s %d %s 22", cfg.ClientIP, cfg.ClientPort, cfg.Host.IP)},
	}
	if cfg.Mode == RunCommand {
		// dropbear's default for root; sh -c does not read /etc/profile.
		env = append(env, [2]string{"PATH", "/usr/sbin:/usr/bin:/sbin:/bin"})
	} else {
		env = append(env, [2]string{"PATH", "/bin:/sbin:/usr/bin:/usr/sbin"}, [2]string{"LD_LIBRARY_PATH", "/lib:/usr/lib"})
	}
	if cfg.Term != "" {
		env = append(env, [2]string{"TERM", cfg.Term}, [2]string{"SSH_TTY", s.tty})
	}
	for k, v := range cfg.Env {
		env = append(env, [2]string{k, v})
	}
	for _, kv := range env {
		s.vars[kv[0]] = kv[1]
		s.exports[kv[0]] = true
	}
	if p, ok := s.kernel.Get(s.pid); ok {
		p.Environ = s.environ(true)
		s.kernel.Add(p)
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
	case "PPID":
		return strconv.Itoa(s.ppid())
	case "RANDOM":
		return strconv.Itoa(s.cfg.Rand.IntN(32768))
	case "LINENO":
		return strconv.Itoa(max(1, s.lineno))
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

func (s *Shell) allocPID() int { return s.kernel.AllocPID(s.cfg.Rand.IntN(3)) }

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

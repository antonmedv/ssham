package shell

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"path"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/vfs"
)

// Env is everything a simulated command can see and do. Commands should
// only use Env, never reach into the shell, so they stay easy to read and
// to test.
type Env struct {
	Ctx    context.Context // cancelled on Ctrl+C or disconnect
	Args   []string        // Args[0] is the command name
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// FS is the filesystem as the current user sees it, with relative
	// paths resolved against the working directory.
	FS *vfs.View

	sh *Shell
	io stdio
}

func (s *Shell) env(ctx context.Context, args []string, io stdio) *Env {
	return &Env{
		Ctx: ctx, Args: args, Stdin: io.in, Stdout: io.out, Stderr: io.err,
		FS: s.view(), sh: s, io: io,
	}
}

// ---- Output ----

// Print writes s to stdout.
func (e *Env) Print(s string) { _, _ = io.WriteString(e.Stdout, s) }

// Printf writes formatted output to stdout.
func (e *Env) Printf(format string, a ...any) { fmt.Fprintf(e.Stdout, format, a...) }

// Errorf writes "applet: message" and a newline to stderr, the way
// BusyBox reports errors (the applet name, even if run as /bin/cat).
func (e *Env) Errorf(format string, a ...any) {
	fmt.Fprintf(e.Stderr, path.Base(e.Args[0])+": "+format+"\n", a...)
}

// Usage prints the applet's BusyBox usage text to stderr and returns 1,
// the way BusyBox reacts to wrong arguments.
func (e *Env) Usage() int {
	fmt.Fprint(e.Stderr, e.sh.usage(path.Base(e.Args[0])))
	return 1
}

// Applets returns every BusyBox applet name and the directory it is linked
// from.
func (e *Env) Applets() map[string]string { return e.sh.cfg.Commands.Applets() }

// RunApplet runs an applet directly, as `busybox ls` does, without
// looking at $PATH. Unknown names fail with "applet not found".
func (e *Env) RunApplet(args ...string) int { return e.sh.busybox(e.Ctx, args[0], args, e.io) }

// IsTTY reports whether stdout is the terminal (not a pipe or file).
func (e *Env) IsTTY() bool { return e.Stdout == e.sh.term }

// Color reports whether output should be colored, as for --color=auto.
func (e *Env) Color() bool { return e.IsTTY() && e.sh.cfg.Term != "" && e.sh.cfg.Term != "dumb" }

// Width is the terminal width in columns.
func (e *Env) Width() int {
	if w, ok := e.sh.term.(interface{ Width() int }); ok && w.Width() > 0 {
		return w.Width()
	}
	return 80
}

// ---- Input ----

// Flags parses the command's arguments. valued lists flags that take a
// value; see ParseFlags.
func (e *Env) Flags(valued ...string) Flags { return ParseFlags(e.Args[1:], valued...) }

// ReadStdin reads all of stdin, up to the capture limit.
func (e *Env) ReadStdin() string {
	b, _ := io.ReadAll(io.LimitReader(e.Stdin, maxCaptureBytes))
	return string(b)
}

// ReadFiles returns the contents of the named files concatenated, or of
// stdin when there are none; "-" also means stdin. Errors are reported the
// BusyBox way, "applet: can't open 'file': error", and make status 1.
func (e *Env) ReadFiles(names []string) (data string, status int) {
	if len(names) == 0 {
		return e.ReadStdin(), 0
	}
	var b strings.Builder
	for _, name := range names {
		if name == "-" {
			b.WriteString(e.ReadStdin())
			continue
		}
		d, err := e.FS.ReadFile(name)
		if err != nil {
			e.Errorf("can't open '%s': %s", name, err)
			status = 1
			continue
		}
		b.Write(d)
	}
	return b.String(), status
}

// Interactive reports whether stdin is the terminal (not a pipe or file).
func (e *Env) Interactive() bool {
	_, ok := e.Stdin.(*ttyReader)
	return ok
}

// ReadLine prompts on the terminal and reads a line; echo false hides the
// input, for passwords. When stdin is piped it reads a line from the pipe
// instead, without prompting, like sudo -S.
func (e *Env) ReadLine(prompt string, echo bool) (string, error) {
	if e.Interactive() {
		return e.sh.term.ReadLine(prompt, echo)
	}
	var b strings.Builder
	var c [1]byte
	for {
		n, err := e.Stdin.Read(c[:])
		if n == 0 || err != nil {
			if b.Len() == 0 {
				return "", io.EOF
			}
			break
		}
		if c[0] == '\n' {
			break
		}
		b.WriteByte(c[0])
	}
	return b.String(), nil
}

// ---- Session ----

// User is the current user (changes under sudo and su).
func (e *Env) User() User { return e.sh.user }

// LookupUser finds an account in /etc/passwd.
func (e *Env) LookupUser(name string) (User, bool) { return lookupUser(e.sh.fs, name) }

// GroupID returns the id of a group in /etc/group, or -1.
func (e *Env) GroupID(name string) int { return groupID(e.sh.fs, name) }

// Host describes the fake machine.
func (e *Env) Host() rootfs.Host { return e.sh.cfg.Host }

// Session describes the attacker's connection.
type Session struct {
	LoginUser string // the user they logged in as
	ClientIP  string
	Started   time.Time
	PID       int    // the login shell's pid ($$)
	Term      string // $TERM, empty without a pty
}

// Session returns information about the connection.
func (e *Env) Session() Session {
	c := e.sh.cfg
	return Session{LoginUser: c.User, ClientIP: c.ClientIP, Started: c.Started, PID: e.sh.pid, Term: c.Term}
}

// NewPID allocates a process id for things like ps showing itself.
func (e *Env) NewPID() int { return e.sh.allocPID() }

// Getenv returns a shell variable.
func (e *Env) Getenv(name string) string { return e.sh.getVar(name) }

// Environ returns the exported variables as sorted NAME=value pairs.
func (e *Env) Environ() []string { return e.sh.environ(true) }

// LookPath finds a program on $PATH.
func (e *Env) LookPath(name string) (string, bool) { return e.sh.lookPath(name) }

// Log records an audit event for this session.
func (e *Env) Log(event string, attrs ...any) { e.sh.log.Event(event, attrs...) }

// ---- Time and randomness ----

// Now is the current time. Use it instead of time.Now so tests are
// deterministic.
func (e *Env) Now() time.Time { return e.sh.now() }

// Rand is the session's random source. Use it instead of math/rand so tests
// are deterministic.
func (e *Env) Rand() *rand.Rand { return e.sh.cfg.Rand }

// Sleep waits for d. It returns false if the command was interrupted.
func (e *Env) Sleep(d time.Duration) bool { return e.sh.cfg.Sleep(e.Ctx, d) }

// ---- Running other commands ----

// Run runs another command with the same stdio, as xargs or nohup do.
func (e *Env) Run(args ...string) int { return e.sh.run(e.Ctx, args, e.io) }

// RunWithVars runs another command with extra environment variables
// ("NAME=value"), as env does.
func (e *Env) RunWithVars(vars []string, args ...string) int {
	return e.sh.withVars(vars, func() int { return e.sh.run(e.Ctx, args, e.io) })
}

// RunWithStdin runs another command with the given stdin.
func (e *Env) RunWithStdin(stdin io.Reader, args ...string) int {
	return e.sh.run(e.Ctx, args, stdio{stdin, e.Stdout, e.Stderr})
}

// RunScript interprets src in a child shell, as sh -c does. args, if
// given, become $0 $1 ...
func (e *Env) RunScript(src string, args ...string) int {
	if len(args) == 0 {
		args = nil
	}
	status, ok := e.sh.nest(true, args, func() int { return e.sh.execString(e.Ctx, src, e.io) })
	if !ok {
		fmt.Fprintf(e.Stderr, "%s: maximum nesting level exceeded\n", e.Args[0])
	}
	return status
}

// RunFile interprets the script at path, with args as $0 $1 ...
func (e *Env) RunFile(path string, args ...string) int {
	data, err := e.FS.ReadFile(path)
	if err != nil {
		fmt.Fprintf(e.Stderr, "sh: can't open '%s': %s\n", path, err)
		return 2
	}
	if len(args) == 0 {
		args = []string{path}
	}
	return e.sh.runScript(e.Ctx, e.FS.Abs(path), data, args, e.io)
}

// Login starts a nested shell as user (su, sudo -i, bash). The attacker
// returns to the current user with exit. If cwd is empty, the working
// directory is kept.
func (e *Env) Login(user User, cwd string) { e.sh.login(user, cwd) }

// Exit ends the session, as reboot does.
func (e *Env) Exit(code int) {
	e.sh.exited = true
	e.sh.exitCode = code
}

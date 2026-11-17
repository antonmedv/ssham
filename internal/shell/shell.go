// Package shell implements a fake bash. Every command is simulated in Go
// against an in-memory filesystem; nothing is ever executed on the host.
package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
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
	Host     vfs.Host
	User     string
	FS       *vfs.FS // the session's private filesystem
	Log      *audit.SessionLogger
	Term     string // $TERM, empty if no pty
	ClientIP string
	Started  time.Time
}

type identity struct {
	user, home, cwd string
	uid             int
}

const (
	maxCaptureBytes = 1 << 20
	maxSubstDepth   = 8
	maxScriptDepth  = 8
	maxLineLen      = 64 << 10
)

// Shell is one fake bash session.
type Shell struct {
	cfg  Config
	fs   *vfs.FS
	term Terminal
	log  *audit.SessionLogger

	user  string
	uid   int
	home  string
	cwd   string
	stack []identity // previous identities for su/sudo -i/nested shells

	vars    map[string]string
	exports map[string]bool
	aliases map[string]string
	history []string
	args    []string // $0 $1 ... for scripts
	status  int
	pid     int
	nextPID int
	jobs    int

	sudoAuthed bool
	depth      int // command substitution / script nesting depth
	exited     bool
	exitCode   int

	mu     sync.Mutex
	cancel context.CancelFunc
}

// New creates a shell for one session.
func New(cfg Config, term Terminal) *Shell {
	if cfg.Started.IsZero() {
		cfg.Started = time.Now()
	}
	uid := 1000
	if cfg.User == "root" {
		uid = 0
	} else if cfg.User != "ubuntu" {
		uid = 1001
	}
	home := vfs.AddUser(cfg.FS, cfg.User, uid)
	s := &Shell{
		cfg:     cfg,
		fs:      cfg.FS,
		term:    term,
		log:     cfg.Log,
		user:    cfg.User,
		uid:     uid,
		home:    home,
		cwd:     home,
		vars:    map[string]string{},
		exports: map[string]bool{},
		aliases: map[string]string{"ls": "ls --color=auto", "grep": "grep --color=auto", "ll": "ls -alF", "la": "ls -A", "l": "ls -CF"},
		pid:     2000 + rand.IntN(30000),
	}
	s.nextPID = s.pid + 1
	for k, v := range map[string]string{
		"SHELL": "/bin/bash", "LANG": "C.UTF-8", "LOGNAME": s.user, "USER": s.user, "HOME": s.home, "PWD": s.cwd,
		"PATH":            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin",
		"SSH_CONNECTION":  fmt.Sprintf("%s %d 10.0.2.15 22", cfg.ClientIP, 40000+rand.IntN(20000)),
		"SSH_CLIENT":      fmt.Sprintf("%s %d 22", cfg.ClientIP, 40000+rand.IntN(20000)),
		"MOTD_SHOWN":      "pam",
		"XDG_SESSION_ID":  fmt.Sprint(rand.IntN(400) + 1),
		"XDG_RUNTIME_DIR": fmt.Sprintf("/run/user/%d", uid),
		"SHLVL":           "1",
	} {
		s.vars[k] = v
		s.exports[k] = true
	}
	if cfg.Term != "" {
		s.vars["TERM"] = cfg.Term
		s.exports["TERM"] = true
		s.vars["SSH_TTY"] = "/dev/pts/0"
		s.exports["SSH_TTY"] = true
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

func (s *Shell) getVar(name string) string {
	switch name {
	case "RANDOM":
		return fmt.Sprint(rand.IntN(32768))
	case "UID":
		return fmt.Sprint(s.uid)
	case "EUID":
		return fmt.Sprint(s.uid)
	case "HOSTNAME":
		return s.cfg.Host.Hostname
	case "BASH_VERSION":
		return "5.2.21(1)-release"
	case "PPID":
		return fmt.Sprint(s.pid - 1)
	case "SECONDS":
		return fmt.Sprint(int(time.Since(s.cfg.Started).Seconds()))
	}
	return s.vars[name]
}

func (s *Shell) setVar(name, val string) {
	s.vars[name] = val
}

// resolve turns a user-supplied path into an absolute one.
func (s *Shell) resolve(p string) string {
	if p == "" {
		return s.cwd
	}
	return vfs.Abs(s.cwd, p)
}

// prettyCwd abbreviates the home directory as ~.
func (s *Shell) prettyCwd() string {
	if s.cwd == s.home {
		return "~"
	}
	if strings.HasPrefix(s.cwd, s.home+"/") {
		return "~" + s.cwd[len(s.home):]
	}
	return s.cwd
}

// Prompt renders PS1 the way Ubuntu's default .bashrc does.
func (s *Shell) Prompt() string {
	sigil := "$"
	if s.uid == 0 {
		sigil = "#"
	}
	host := s.cfg.Host.Hostname
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	if strings.Contains(s.cfg.Term, "color") || strings.HasPrefix(s.cfg.Term, "xterm") {
		return fmt.Sprintf("\x1b[01;32m%s@%s\x1b[00m:\x1b[01;34m%s\x1b[00m%s ", s.user, host, s.prettyCwd(), sigil)
	}
	return fmt.Sprintf("%s@%s:%s%s ", s.user, host, s.prettyCwd(), sigil)
}

// Run runs the interactive read-eval loop until the attacker exits or the
// context is cancelled.
func (s *Shell) Run(ctx context.Context) int {
	for !s.exited && ctx.Err() == nil {
		line, err := s.term.ReadLine(s.Prompt(), true)
		if errors.Is(err, ErrInterrupt) {
			s.status = 130
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.log.Event("input", "line", "^D")
				if s.popIdentity() {
					s.write("exit\n")
					continue
				}
				if s.cfg.Term != "" {
					s.write("logout\n")
				}
			}
			break
		}
		s.log.Event("input", "line", line)
		s.addHistory(line)
		s.Exec(ctx, line)
	}
	return s.exitCode
}

func (s *Shell) addHistory(line string) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(line, " ") {
		return
	}
	if n := len(s.history); n > 0 && s.history[n-1] == line {
		return
	}
	s.history = append(s.history, line)
	if len(s.history) > 1000 {
		s.history = s.history[1:]
	}
}

// History returns the command history, oldest first.
func (s *Shell) History() []string { return s.history }

func (s *Shell) write(str string) { _, _ = io.WriteString(s.term, str) }

// Exec runs one line of input with output going to the terminal.
func (s *Shell) Exec(ctx context.Context, line string) int {
	if len(line) > maxLineLen {
		line = line[:maxLineLen]
	}
	cctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()
		cancel()
	}()
	defer func() {
		// A bug in a simulated command must not take down the honeypot.
		if r := recover(); r != nil {
			s.log.Event("panic", "line", line, "panic", fmt.Sprint(r))
			s.write("Segmentation fault (core dumped)\n")
			s.status = 139
		}
	}()
	return s.execString(cctx, line, &ttyReader{s: s}, s.term, s.term)
}

func (s *Shell) execString(ctx context.Context, src string, stdin io.Reader, stdout, stderr io.Writer) int {
	l, err := parse(src)
	if err != nil {
		fmt.Fprintf(stderr, "-bash: %v\n", err)
		s.status = 2
		return s.status
	}
	return s.runList(ctx, l, stdin, stdout, stderr)
}

func (s *Shell) runList(ctx context.Context, l *list, stdin io.Reader, stdout, stderr io.Writer) int {
	prevOp := ";"
	for i, pl := range l.items {
		if s.exited || ctx.Err() != nil {
			break
		}
		skip := (prevOp == "&&" && s.status != 0) || (prevOp == "||" && s.status == 0)
		prevOp = l.ops[i]
		if skip {
			continue
		}
		if l.ops[i] == "&" {
			// Pretend to background the job; actually run it with no
			// terminal input so it cannot block.
			s.jobs++
			fmt.Fprintf(stderr, "[%d] %d\n", s.jobs, s.allocPID())
			s.status = s.runPipeline(ctx, pl, strings.NewReader(""), stdout, stderr)
			s.status = 0
			continue
		}
		s.status = s.runPipeline(ctx, pl, stdin, stdout, stderr)
	}
	if ctx.Err() != nil && s.depth == 0 {
		s.status = 130
	}
	return s.status
}

func (s *Shell) allocPID() int {
	s.nextPID += 1 + rand.IntN(7)
	return s.nextPID
}

// runPipeline runs the commands one after another, feeding each one's
// output to the next. Commands are simulated, so there is no need for
// real concurrency.
func (s *Shell) runPipeline(ctx context.Context, pl *pipeline, stdin io.Reader, stdout, stderr io.Writer) int {
	in := stdin
	status := 0
	for i, c := range pl.cmds {
		var out io.Writer = stdout
		var buf *limitedBuffer
		if i < len(pl.cmds)-1 {
			buf = &limitedBuffer{max: maxCaptureBytes}
			out = buf
		}
		status = s.runCommand(ctx, c, in, out, stderr)
		if buf != nil {
			in = bytes.NewReader(buf.Bytes())
		}
		if s.exited {
			break
		}
	}
	return status
}

func (s *Shell) runCommand(ctx context.Context, c *command, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		return 130
	}
	// Apply redirections.
	var flush []func()
	defer func() {
		for _, f := range flush {
			f()
		}
	}()
	for _, r := range c.redirs {
		target := s.expandOne(ctx, r.target)
		switch r.op {
		case ">&":
			if target == "1" {
				if r.fd == 2 {
					stderr = stdout
				}
				continue
			}
			if target == "2" {
				if r.fd == 1 {
					stdout = stderr
				}
				continue
			}
			if target == "-" {
				continue
			}
			fallthrough
		case ">", ">>", "&>", "&>>":
			appendMode := r.op == ">>" || r.op == "&>>"
			p := s.resolve(target)
			if target == "" {
				fmt.Fprintf(stderr, "-bash: %s: ambiguous redirect\n", r.target)
				return 1
			}
			if p == "/dev/null" {
				if r.op == "&>" || r.op == "&>>" || r.op == ">&" {
					stdout, stderr = io.Discard, io.Discard
				} else if r.fd == 2 {
					stderr = io.Discard
				} else {
					stdout = io.Discard
				}
				continue
			}
			// Truncate (or create) now, so errors show up before the
			// command runs, like in bash.
			if err := s.fs.WriteFile(s.user, p, nil, appendMode); err != nil {
				fmt.Fprintf(stderr, "-bash: %s: %s\n", target, err)
				return 1
			}
			buf := &limitedBuffer{max: maxCaptureBytes}
			flush = append(flush, func() {
				if buf.Len() > 0 {
					if err := s.fs.WriteFile(s.user, p, buf.Bytes(), true); err != nil {
						fmt.Fprintf(stderr, "-bash: %s: %s\n", target, err)
					}
				}
			})
			switch {
			case r.op == "&>" || r.op == "&>>" || r.op == ">&":
				stdout, stderr = buf, buf
			case r.fd == 2:
				stderr = buf
			default:
				stdout = buf
			}
		case "<", "<>":
			data, err := s.fs.ReadFile(s.user, s.resolve(target))
			if err != nil {
				fmt.Fprintf(stderr, "-bash: %s: %s\n", target, err)
				return 1
			}
			stdin = bytes.NewReader(data)
		case "<<<":
			stdin = strings.NewReader(target + "\n")
		case "<&":
			// ignore fd duplication for input
		}
	}

	if c.group != nil {
		return s.runList(ctx, c.group, stdin, stdout, stderr)
	}

	if len(c.words) == 0 {
		for _, a := range c.assigns {
			name, val, _ := strings.Cut(a, "=")
			s.setVar(name, s.expandOne(ctx, val))
		}
		return 0
	}

	args := s.expandWords(ctx, c.words)
	if len(args) == 0 {
		return 0
	}
	// Alias expansion applies to an unquoted first word.
	if a, ok := s.aliases[args[0]]; ok && c.words[0] == args[0] {
		args = append(strings.Fields(a), args[1:]...)
	}

	// VAR=value cmd: set for the duration of this command only.
	if len(c.assigns) > 0 {
		saved := map[string]*string{}
		for _, a := range c.assigns {
			name, val, _ := strings.Cut(a, "=")
			if old, ok := s.vars[name]; ok {
				saved[name] = &old
			} else {
				saved[name] = nil
			}
			s.setVar(name, s.expandOne(ctx, val))
		}
		defer func() {
			for name, old := range saved {
				if old == nil {
					delete(s.vars, name)
				} else {
					s.vars[name] = *old
				}
			}
		}()
	}

	return s.run(ctx, args, stdin, stdout, stderr)
}

// run dispatches argv to a builtin, a simulated program, or a script.
func (s *Shell) run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	name := args[0]
	e := &Env{Ctx: ctx, Args: args, Stdin: stdin, Stdout: stdout, Stderr: stderr, sh: s}

	if strings.Contains(name, "/") {
		return s.runPath(e)
	}
	if fn, ok := builtins[name]; ok {
		return fn(e)
	}
	if _, ok := s.lookPath(name); ok {
		if fn, ok := commands[name]; ok {
			return fn(e)
		}
		// Installed but not simulated: behave like it ran and printed nothing.
		return 0
	}
	fmt.Fprintf(stderr, "%s: command not found\n", name)
	return 127
}

// lookPath searches $PATH in the virtual filesystem.
func (s *Shell) lookPath(name string) (string, bool) {
	for _, dir := range strings.Split(s.getVar("PATH"), ":") {
		if dir == "" {
			continue
		}
		p := dir + "/" + name
		if n, err := s.fs.Stat(s.user, p); err == nil && !n.IsDir() && n.Mode.Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// runPath handles ./script.sh, /usr/bin/ls and similar.
func (s *Shell) runPath(e *Env) int {
	name := e.Args[0]
	p := s.resolve(name)
	n, err := s.fs.Stat(s.user, p)
	if err != nil {
		fmt.Fprintf(e.Stderr, "-bash: %s: %s\n", name, err)
		return 127
	}
	if n.IsDir() {
		fmt.Fprintf(e.Stderr, "-bash: %s: Is a directory\n", name)
		return 126
	}
	if !vfs.CanAccess(n, s.user, 1) {
		fmt.Fprintf(e.Stderr, "-bash: %s: Permission denied\n", name)
		return 126
	}
	base := p[strings.LastIndexByte(p, '/')+1:]
	if fn, ok := commands[base]; ok && (strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/bin/") || strings.HasPrefix(p, "/sbin/")) {
		return fn(e)
	}
	data, _ := s.fs.ReadFile("root", p)
	if bytes.HasPrefix(data, []byte("\x7fELF")) {
		if n.FakeSize > 0 {
			return 0 // a stock binary we don't simulate
		}
		// A dropped payload: pretend it crashed.
		s.log.Event("exec_binary", "path", p, "args", strings.Join(e.Args[1:], " "))
		fmt.Fprintln(e.Stderr, "Segmentation fault (core dumped)")
		return 139
	}
	if len(data) > 0 && !isText(data) {
		s.log.Event("exec_binary", "path", p, "size", len(data))
		fmt.Fprintf(e.Stderr, "-bash: %s: cannot execute binary file: Exec format error\n", name)
		return 126
	}
	return s.runScript(e, p, data)
}

func isText(b []byte) bool {
	if len(b) > 512 {
		b = b[:512]
	}
	return !bytes.ContainsRune(b, 0)
}

// runScript interprets a shell script from the virtual filesystem.
func (s *Shell) runScript(e *Env, p string, data []byte) int {
	if s.depth >= maxScriptDepth {
		fmt.Fprintf(e.Stderr, "-bash: %s: maximum nesting level exceeded\n", e.Args[0])
		return 1
	}
	s.log.Event("exec_script", "path", p, "content", truncate(string(data), 4096))
	savedArgs := s.args
	s.args = e.Args
	s.depth++
	defer func() {
		s.args = savedArgs
		s.depth--
	}()
	return s.execString(e.Ctx, string(data), e.Stdin, e.Stdout, e.Stderr)
}

// commandSubst runs src and returns its output with trailing newlines
// removed, as $(...) does.
func (s *Shell) commandSubst(ctx context.Context, src string) string {
	if s.depth >= maxSubstDepth {
		return ""
	}
	s.depth++
	defer func() { s.depth-- }()
	var out limitedBuffer
	out.max = maxCaptureBytes
	s.execString(ctx, src, strings.NewReader(""), &out, s.term)
	return strings.TrimRight(out.String(), "\n")
}

// Capture runs a line non-interactively and returns its combined output.
// It is used for `ssh host command` exec requests.
func (s *Shell) Capture(ctx context.Context, line string, stdin io.Reader) (output string, code int) {
	var out limitedBuffer
	out.max = maxCaptureBytes
	defer func() {
		if r := recover(); r != nil {
			s.log.Event("panic", "line", line, "panic", fmt.Sprint(r))
			out.WriteString("Segmentation fault (core dumped)\n")
			output, code = out.String(), 139
		}
	}()
	code = s.execString(ctx, line, stdin, &out, &out)
	if s.exited {
		code = s.exitCode
	}
	return out.String(), code
}

func (s *Shell) pushIdentity(user, home string, uid int, cwd string) {
	s.stack = append(s.stack, identity{user: s.user, home: s.home, cwd: s.cwd, uid: s.uid})
	s.user, s.home, s.uid = user, home, uid
	if cwd != "" {
		s.cwd = cwd
	}
	s.vars["USER"], s.vars["LOGNAME"], s.vars["HOME"], s.vars["PWD"] = user, user, home, s.cwd
	s.vars["SHLVL"] = fmt.Sprint(len(s.stack) + 1)
}

func (s *Shell) popIdentity() bool {
	if len(s.stack) == 0 {
		return false
	}
	id := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	s.user, s.home, s.uid, s.cwd = id.user, id.home, id.uid, id.cwd
	s.vars["USER"], s.vars["LOGNAME"], s.vars["HOME"], s.vars["PWD"] = id.user, id.user, id.home, id.cwd
	s.vars["SHLVL"] = fmt.Sprint(len(s.stack) + 1)
	return true
}

func (s *Shell) sortedVars(exportedOnly bool) []string {
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

// ttyReader lets commands like a bare `cat` read lines from the terminal.
type ttyReader struct {
	s   *Shell
	buf []byte
	eof bool
}

func (r *ttyReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		if r.eof {
			return 0, io.EOF
		}
		line, err := r.s.term.ReadLine("", true)
		if err != nil {
			r.eof = true
			if errors.Is(err, ErrInterrupt) {
				r.s.Interrupt()
			}
			return 0, io.EOF
		}
		r.s.log.Event("stdin", "line", line)
		r.buf = []byte(line + "\n")
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// limitedBuffer is a bytes.Buffer that silently drops data past max.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room < len(p) {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

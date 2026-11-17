package shell

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/vfs"
)

// stdio is the standard input and outputs of a command.
type stdio struct {
	in       io.Reader
	out, err io.Writer
}

// Exec runs one line of interactive input with the terminal as stdio.
// Ctrl+C (Interrupt) cancels it.
func (s *Shell) Exec(ctx context.Context, line string) (status int) {
	ctx, cancel := context.WithCancel(ctx)
	s.resetBudget(ctx)
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
			s.log.Event(audit.Panic, "line", line, "panic", fmt.Sprint(r))
			s.write("Segmentation fault\n")
			s.status, status = 139, 139
		}
	}()
	return s.execString(ctx, line, stdio{&ttyReader{s: s}, s.term, s.term})
}

// Command runs line the way `ssh host 'line'` does, writing output as it
// is produced.
func (s *Shell) Command(ctx context.Context, line string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	s.resetBudget(ctx)
	defer func() {
		if r := recover(); r != nil {
			s.log.Event(audit.Panic, "line", line, "panic", fmt.Sprint(r))
			fmt.Fprint(stderr, "Segmentation fault\n")
			code = 139
		}
	}()
	if p, ok := s.kernel.Get(s.pid); ok {
		p.Cmdline = []string{"sh", "-c", line}
		s.kernel.Add(p)
	}
	code = s.execString(ctx, line, stdio{stdin, stdout, stderr})
	if s.exited {
		code = s.exitCode
	}
	s.runExitTrap(ctx, stdio{strings.NewReader(""), stdout, stderr})
	return code
}

// Capture runs a line like Command and returns its combined output.
func (s *Shell) Capture(ctx context.Context, line string, stdin io.Reader) (output string, code int) {
	out := &limitedBuffer{max: maxCaptureBytes}
	code = s.Command(ctx, line, stdin, out, out)
	return out.String(), code
}

func (s *Shell) execString(ctx context.Context, src string, std stdio) int {
	if len(src) > maxLineLen {
		src = src[:maxLineLen]
	}
	l, err := parse(src)
	if err != nil {
		fmt.Fprintf(std.err, "sh: %v\n", err)
		s.status = 2
		return s.status
	}
	return s.runList(ctx, l, std)
}

// runList runs commands joined by ; & && ||.
func (s *Shell) runList(ctx context.Context, l *list, std stdio) int {
	prevOp := ";"
	for i, pl := range l.items {
		if sig := s.signaled.Load(); sig != 0 {
			s.exited, s.exitCode = true, 128+int(sig)
		}
		if s.pendingSig.Load() != 0 {
			s.runPendingTrap(ctx, std)
		}
		if s.exited || s.leaving || s.jump != 0 || ctx.Err() != nil || s.aborted {
			break
		}
		skip := (prevOp == "&&" && s.status != 0) || (prevOp == "||" && s.status == 0)
		prevOp = l.ops[i]
		if skip {
			continue
		}
		if l.ops[i] == "&" {
			s.startJob(ctx, pl, std)
			s.status = 0
			continue
		}
		// A failure on the left of && or || is not an error for set -e.
		cond := l.ops[i] == "&&" || l.ops[i] == "||"
		if cond {
			s.condDepth++
		}
		s.status = s.runPipeline(ctx, pl, std)
		if cond {
			s.condDepth--
		}
		if s.opts['e'] && s.status != 0 && !cond && s.condDepth == 0 && !pl.negate {
			s.exitShell(s.status)
		}
	}
	if ctx.Err() != nil && s.depth == 0 {
		s.status = 130
	}
	if s.exiting && s.depth == 0 {
		// exit ran in a function called from the top level.
		s.exiting, s.leaving = false, false
		s.exited, s.exitCode = true, s.status
	}
	return s.status
}

// runPipeline runs the commands one after another, feeding each one's
// output to the next. Commands are simulated, so there is no need for real
// concurrency.
func (s *Shell) runPipeline(ctx context.Context, pl *pipeline, std stdio) int {
	in := std.in
	status := 0
	// All stages of a real pipeline run at once, so ps | grep x shows
	// the grep too.
	pids := make([]int, len(pl.cmds))
	if len(pl.cmds) > 1 {
		for i, c := range pl.cmds {
			if len(c.words) > 0 {
				pids[i] = s.allocPID()
				s.spawn(pids[i], rawArgs(c.words), "", 'S')
			}
		}
		defer func() {
			for _, pid := range pids {
				s.reap(pid)
			}
		}()
	}
	for i, c := range pl.cmds {
		s.stagePID = pids[i]
		cio := stdio{in, std.out, std.err}
		var buf *limitedBuffer
		if i < len(pl.cmds)-1 {
			buf = &limitedBuffer{max: maxCaptureBytes}
			cio.out = buf
		}
		if len(pl.cmds) > 1 {
			// Every stage of a pipeline is a subshell in ash: echo x |
			// read v sets v only there.
			status, _ = s.nest(true, nil, func() int { return s.runCommand(ctx, c, cio) })
		} else {
			status = s.runCommand(ctx, c, cio)
		}
		s.stagePID = 0
		if buf != nil {
			in = bytes.NewReader(buf.Bytes())
			if buf.endless {
				in = &endlessReader{bytes.NewReader(buf.Bytes())}
			}
		}
		if s.exited || s.leaving {
			break
		}
	}
	if pl.negate {
		if status == 0 {
			return 1
		}
		return 0
	}
	return status
}

func (s *Shell) runCommand(ctx context.Context, c *command, std stdio) int {
	if ctx.Err() != nil {
		return 130
	}
	if !s.step() {
		return 130
	}
	savedErr := s.errOut
	s.errOut = std.err
	defer func() { s.errOut = savedErr }()
	s.substRan = false
	std, flush, ok := s.redirect(ctx, c.redirs, std)
	defer flush()
	if !s.checkExpand(std.err) {
		return 2
	}
	if !ok {
		return 1
	}

	switch {
	case c.subshell != nil:
		status, _ := s.nest(true, nil, func() int { return s.runList(ctx, c.subshell, std) })
		return status
	case c.brace != nil:
		return s.runList(ctx, c.brace, std)
	case c.ifc != nil:
		return s.runIf(ctx, c.ifc, std)
	case c.loop != nil:
		return s.runLoop(ctx, c.loop, std)
	case c.forc != nil:
		return s.runFor(ctx, c.forc, std)
	case c.casec != nil:
		return s.runCase(ctx, c.casec, std)
	case c.fn != nil:
		s.funcs[c.fn.name] = c.fn.body
		return 0
	}

	// Plain assignments: X=1 Y=2. The status is that of the last $(...)
	// in them, if any.
	if len(c.words) == 0 {
		for _, a := range c.assigns {
			name, val, _ := strings.Cut(a, "=")
			s.setVar(name, s.expandOne(ctx, val))
		}
		if !s.checkExpand(std.err) {
			return 2
		}
		if s.substRan {
			return s.substCode
		}
		return 0
	}

	args := s.expandWords(ctx, c.words)
	if !s.checkExpand(std.err) {
		return 2
	}
	if len(args) == 0 {
		return 0
	}
	// Alias expansion applies to an unquoted first word.
	if a, ok := s.aliases[args[0]]; ok && c.words[0] == args[0] {
		args = append(strings.Fields(a), args[1:]...)
	}

	// X=1 cmd: the variable is exported to this command only.
	if len(c.assigns) > 0 {
		var vars []string
		for _, a := range c.assigns {
			name, val, _ := strings.Cut(a, "=")
			vars = append(vars, name+"="+s.expandOne(ctx, val))
		}
		return s.withVars(vars, func() int { return s.run(ctx, args, std) })
	}
	return s.run(ctx, args, std)
}

// withVars runs fn with extra exported variables ("NAME=value"), then
// restores the previous ones.
func (s *Shell) withVars(vars []string, fn func() int) int {
	savedVars, savedExports := maps.Clone(s.vars), maps.Clone(s.exports)
	defer func() { s.vars, s.exports = savedVars, savedExports }()
	for _, kv := range vars {
		name, val, _ := strings.Cut(kv, "=")
		s.vars[name] = val
		s.exports[name] = true
	}
	return fn()
}

// Work limits for one command line, so an attacker cannot make the
// honeypot spin: a fork bomb runs out of processes (as a 64 MB camera
// would), and endless work looks like a hung device.
const (
	maxForks = 2000   // processes and subshells
	maxSteps = 100000 // simple commands and function calls
)

// resetBudget starts the limits over for a new command line.
func (s *Shell) resetBudget(ctx context.Context) {
	if s.depth == 0 && s.ffwd == nil {
		s.forks, s.steps, s.aborted, s.crashed = 0, 0, false, false
		s.runCtx = ctx
	}
}

// fork accounts for a new process; false means there is none left, and
// the device has hung, as a 64 MB camera does under a fork bomb.
func (s *Shell) fork() bool {
	s.forks++
	if s.forks > maxForks {
		s.hang()
	}
	return !s.aborted
}

// step accounts for a unit of work; past the limit the device hangs.
func (s *Shell) step() bool {
	s.steps++
	if s.steps > maxSteps {
		s.hang()
	}
	return !s.aborted
}

// hang makes the command line stop responding, then abandons it.
func (s *Shell) hang() {
	if s.aborted {
		return
	}
	ctx := s.runCtx
	if ctx == nil {
		ctx = context.Background()
	}
	s.sleep(ctx, 24*time.Hour)
	s.aborted = true
}

// inChild reports whether the code running is in a child shell: a
// subshell, sh -c, a script, $(...) or a pipeline stage.
func (s *Shell) inChild() bool { return s.children > 0 }

// overflow is what endless recursion does to ash: it runs out of stack
// and dies. A child shell's death is reported by its parent (see nest);
// the login shell's ends the session.
func (s *Shell) overflow() {
	if s.children >= 8 {
		// Recursion through subshells, pipelines or & is a fork bomb:
		// processes pile up until the device stops responding.
		s.hang()
		return
	}
	s.crashed, s.aborted = true, true
	if s.depth == 0 || !s.inChild() {
		s.exited, s.exitCode = true, 139
	}
}

// maxIterations bounds a loop. A loop that runs longer is treated as
// endless: it waits like a hung command, until Ctrl+C or disconnect,
// instead of burning CPU.
const maxIterations = 10000

// exitShell is what exit does, for set -e and kill.
func (s *Shell) exitShell(code int) {
	s.exitCode = code
	if s.funcDepth > 0 {
		s.exiting = true
	}
	if s.depth > 0 {
		s.leaving = true
		return
	}
	s.exited = true
}

func (s *Shell) runIf(ctx context.Context, c *ifClause, std stdio) int {
	for i, cond := range c.conds {
		s.condDepth++
		s.runList(ctx, cond, std)
		s.condDepth--
		if s.jump != 0 || s.exited || s.leaving {
			return s.status
		}
		if s.status == 0 {
			return s.runList(ctx, c.bodies[i], std)
		}
	}
	if c.elseBody != nil {
		return s.runList(ctx, c.elseBody, std)
	}
	return 0
}

func (s *Shell) runLoop(ctx context.Context, c *loopClause, std stdio) int {
	return s.loop(ctx, func(i int) bool {
		s.condDepth++
		s.runList(ctx, c.cond, std)
		s.condDepth--
		return (s.status == 0) != c.until
	}, c.body, std)
}

func (s *Shell) runFor(ctx context.Context, c *forClause, std stdio) int {
	items := s.args[min(1, len(s.args)):]
	if c.in {
		items = s.expandWords(ctx, c.words)
	}
	return s.loop(ctx, func(i int) bool {
		if i >= len(items) {
			return false
		}
		s.setVar(c.name, items[i])
		return true
	}, c.body, std)
}

// loop runs body while next(i) is true, handling break, continue and
// endless loops.
func (s *Shell) loop(ctx context.Context, next func(i int) bool, body *list, std stdio) int {
	s.loopDepth++
	defer func() { s.loopDepth-- }()
	status := 0
	for i := 0; ; i++ {
		if i == maxIterations {
			s.sleep(ctx, 24*time.Hour)
			return 130
		}
		if ctx.Err() != nil || s.exited || s.leaving || s.aborted || !next(i) || s.jump != 0 {
			break
		}
		status = s.runList(ctx, body, std)
		if s.jump > 0 { // break
			s.jump--
			break
		}
		if s.jump < 0 { // continue
			s.jump++
			if s.jump < 0 {
				break // continue N: continue an outer loop
			}
		}
	}
	return status
}

// redirect applies redirections to std. Output redirected to a file is
// buffered and written when flush is called. ok is false if a redirection
// failed (the error has been printed).
func (s *Shell) redirect(ctx context.Context, redirs []redir, std stdio) (_ stdio, flush func(), ok bool) {
	var flushes []func()
	flush = func() {
		for _, f := range flushes {
			f()
		}
	}
	for _, r := range redirs {
		target := r.target
		if r.doc == nil {
			target = s.expandOne(ctx, r.target)
		}
		both := r.op == "&>" || r.op == "&>>"
		switch r.op {
		case ">&":
			switch target {
			case "1":
				if r.fd == 2 {
					std.err = std.out
				}
				continue
			case "2":
				if r.fd == 1 {
					std.out = std.err
				}
				continue
			case "-":
				continue
			}
			both = true // >&file is the same as &>file
			fallthrough
		case ">", ">>", "&>", "&>>":
			if target == "" {
				fmt.Fprintln(std.err, "sh: can't create : nonexistent directory")
				return std, flush, false
			}
			var w io.Writer
			if s.resolve(target) == "/dev/null" {
				w = io.Discard
			} else {
				f, err := s.openOutput(target, r.op == ">>" || r.op == "&>>", std.err)
				if err != nil {
					fmt.Fprintf(std.err, "sh: can't create %s: %s\n", target, ashError(err, true))
					return std, flush, false
				}
				flushes = append(flushes, f.flush)
				w = f
			}
			switch {
			case both:
				std.out, std.err = w, w
			case r.fd == 2:
				std.err = w
			default:
				std.out = w
			}
		case "<", "<>":
			data, err := s.view().ReadFile(target)
			if err != nil {
				fmt.Fprintf(std.err, "sh: can't open %s: %s\n", target, ashError(err, false))
				return std, flush, false
			}
			std.in = bytes.NewReader(data)
			if n, err := s.view().Stat(target); err == nil && vfs.IsEndless(n) {
				std.in = &endlessReader{bytes.NewReader(data)}
			}
		case "<<<":
			std.in = strings.NewReader(target + "\n")
		case "<<", "<<-":
			if r.doc != nil {
				std.in = strings.NewReader(s.heredocText(ctx, r.doc))
			}
		}
	}
	return std, flush, true
}

// fileOutput collects a command's output for a redirected file.
type fileOutput struct {
	limitedBuffer
	view   *vfs.View
	name   string
	stderr io.Writer
}

// openOutput creates or truncates the file now, so errors appear before the
// command runs, like in bash.
func (s *Shell) openOutput(name string, appendMode bool, stderr io.Writer) (*fileOutput, error) {
	v := s.view()
	var err error
	if appendMode {
		err = v.AppendFile(name, nil)
	} else {
		err = v.WriteFile(name, nil)
	}
	if err != nil {
		return nil, err
	}
	return &fileOutput{limitedBuffer: limitedBuffer{max: maxCaptureBytes}, view: v, name: name, stderr: stderr}, nil
}

func (f *fileOutput) flush() {
	if f.Len() == 0 {
		return
	}
	if err := f.view.AppendFile(f.name, f.Bytes()); err != nil {
		fmt.Fprintf(f.stderr, "sh: can't create %s: %s\n", f.name, ashError(err, true))
	}
}

// busyboxPath is the multi-call binary that every applet links to.
const busyboxPath = "/bin/busybox"

// run dispatches argv to a builtin, an applet on $PATH, or a file.
func (s *Shell) run(ctx context.Context, args []string, std stdio) int {
	if s.opts['x'] {
		fmt.Fprintf(std.err, "%s%s\n", s.renderPrompt(s.getVar("PS4")), strings.Join(args, " "))
	}
	name := args[0]
	if strings.Contains(name, "/") {
		return s.runPath(ctx, args, std)
	}
	if fn, ok := s.funcs[name]; ok && !specialBuiltins[name] {
		return s.callFunction(ctx, fn, args, std)
	}
	if b, ok := builtins[name]; ok {
		return s.call(b.run, s.env(ctx, args, std))
	}
	if p, ok := s.lookPath(name); ok {
		return s.exec(ctx, p, args, std)
	}
	fmt.Fprintf(std.err, "sh: %s: not found\n", name)
	return 127
}

// applet returns the implementation of a BusyBox applet, or nil.
func (s *Shell) applet(name string) func(*Env) int {
	if c, ok := s.cfg.Commands.Lookup(name); ok {
		return c.Run
	}
	if b, ok := builtins[name]; ok && b.dir != "" {
		return b.run
	}
	return nil
}

// busybox runs an applet the way the multi-call binary picks it: by the
// name it was invoked as.
func (s *Shell) busybox(ctx context.Context, name string, args []string, std stdio) int {
	run := s.applet(name)
	if run == nil {
		fmt.Fprintf(std.err, "%s: applet not found\n", name)
		return 127
	}
	if _, ok := s.cfg.Commands.Lookup(name); ok && len(args) > 1 && args[1] == "--help" {
		fmt.Fprint(std.out, s.usage(name))
		return 0
	}
	return s.call(run, s.env(ctx, args, std))
}

// usage renders an applet's BusyBox usage text.
func (s *Shell) usage(name string) string {
	text := "No help available"
	if c, ok := s.cfg.Commands.Lookup(name); ok && c.Usage != "" {
		text = "Usage: " + name + " " + c.Usage
	}
	return rootfs.BusyBox + " multi-call binary.\n\n" + text + "\n"
}

// lookPath searches $PATH in the virtual filesystem.
func (s *Shell) lookPath(name string) (string, bool) {
	for _, dir := range strings.Split(s.getVar("PATH"), ":") {
		if dir == "" {
			continue
		}
		p := dir + "/" + name
		if n, err := s.fs.Stat(s.user.Name, p); err == nil && !n.IsDir() && n.Mode.Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// runPath handles ./script.sh, /bin/ls and friends.
func (s *Shell) runPath(ctx context.Context, args []string, std stdio) int {
	name := args[0]
	v := s.view()
	n, err := v.Stat(name)
	switch {
	case errors.Is(err, vfs.ErrNotExist):
		fmt.Fprintf(std.err, "sh: %s: not found\n", name)
		return 127
	case err != nil, n.IsDir(), !v.Can(n, vfs.Exec):
		fmt.Fprintf(std.err, "sh: %s: Permission denied\n", name)
		return 126
	}
	return s.exec(ctx, v.Abs(name), args, std)
}

// exec runs the executable file at p.
func (s *Shell) exec(ctx context.Context, p string, args []string, std stdio) int {
	// BusyBox is recognized by the binary itself, so copies and links to
	// it work too, as they would on the device.
	pid := s.stagePID
	s.stagePID = 0
	if pid == 0 {
		if !s.fork() {
			return 130
		}
		pid = s.allocPID()
	}
	// A program of the firmware has its content made up when read (see
	// vfs.Node.FakeSize): its header and strings say what it is, without
	// making up a megabyte on every command.
	var data []byte
	bb := false
	if n, err := s.fs.Stat("root", p); err == nil && n.FakeSize > 0 {
		data, bb = n.Data, n.FakeSize == busyboxSize && len(n.Strings) > 0
	} else {
		data, _ = s.fs.ReadFile("root", p)
		bb = isBusybox(data)
	}
	script := !bytes.HasPrefix(data, []byte("\x7fELF")) && isText(data)
	exe := p
	if bb {
		exe = "/bin/busybox"
	} else if script {
		exe = "/bin/busybox" // ash runs the script itself
	}
	s.spawn(pid, args, exe, 'R')
	defer s.reap(pid)
	s.syncProc(pid)
	savedExec := s.execPID
	s.execPID = pid
	defer func() { s.execPID = savedExec }()

	if exe == "/bin/busybox" && !script {
		return s.busybox(ctx, path.Base(args[0]), args, std)
	}
	if script {
		saved := s.pid
		s.pid = pid
		defer func() { s.pid = saved }()
		return s.runScript(ctx, p, data, args, std)
	}
	// A binary other than BusyBox, most likely a dropped payload. It is
	// never run: an ARM binary "crashes", and one for another CPU fails the
	// way ash fails on it (exec fails, so ash reads it as a script).
	arch := elfArch(data)
	sum := sha256.Sum256(data)
	s.log.Event(audit.ExecBinary, "path", p, "args", strings.Join(args[1:], " "),
		"arch", arch, "size", len(data), "sha256", hex.EncodeToString(sum[:]))
	if arch == "arm" {
		fmt.Fprintln(std.err, "Segmentation fault")
		return 139
	}
	fmt.Fprintf(std.err, "%s: line 1: syntax error: unexpected \"(\"\n", args[0])
	return 2
}

// elfArch names the CPU an ELF binary is built for.
func elfArch(data []byte) string {
	if len(data) < 20 || !bytes.HasPrefix(data, []byte("\x7fELF")) {
		return "none"
	}
	machine := uint16(data[18]) | uint16(data[19])<<8
	if data[5] == 2 { // big endian
		machine = uint16(data[18])<<8 | uint16(data[19])
	}
	switch machine {
	case 3:
		return "x86"
	case 8:
		return "mips"
	case 20:
		return "powerpc"
	case 40:
		return "arm"
	case 42:
		return "superh"
	case 62:
		return "x86-64"
	case 183:
		return "aarch64"
	}
	return fmt.Sprintf("machine-%d", machine)
}

// call runs a command, turning a panic (a bug in the simulation) into a
// crash of that one command, the way a segfault would look.
func (s *Shell) call(run func(*Env) int, e *Env) (status int) {
	defer func() {
		if r := recover(); r != nil {
			if r == errEndless {
				status = 130 // interrupted while reading forever
				return
			}
			s.log.Event(audit.Panic, "command", strings.Join(e.Args, " "), "panic", fmt.Sprint(r))
			fmt.Fprintln(e.Stderr, "Segmentation fault")
			status = 139
		}
	}()
	status = run(e)
	// A filter that read an endless stream passes it on down the pipe.
	if buf, pipe := e.Stdout.(*limitedBuffer); e.endless && pipe && !prefixReaders[path.Base(e.Args[0])] {
		buf.endless = true
	}
	return status
}

// nest runs fn one level deeper: in a script, sh -c, $(...), ( ... ) or a
// sourced file. exit inside it only ends that level. With isolate, it is a
// child shell: changes to the working directory, variables and aliases do
// not leak back to the parent. args, if not nil, become $0 $1 ...
// ok is false if the nesting limit was reached.
func (s *Shell) nest(isolate bool, args []string, fn func() int) (status int, ok bool) {
	if s.depth >= maxDepth {
		s.overflow()
		return 139, false
	}
	if isolate && !s.fork() {
		return 2, true
	}
	if isolate {
		s.children++
		defer func() { s.children-- }()
	}
	savedArgs := s.args
	var saved struct {
		cwd           string
		vars, aliases map[string]string
		exports       map[string]bool
	}
	var savedTraps, savedFuncs = s.traps, s.funcs
	var savedOpts = s.opts
	if isolate {
		saved.cwd, saved.vars, saved.exports, saved.aliases = s.cwd, maps.Clone(s.vars), maps.Clone(s.exports), maps.Clone(s.aliases)
		// A child shell inherits functions and options, and starts with
		// no traps of its own.
		s.traps, s.funcs, s.opts = map[string]string{}, maps.Clone(s.funcs), maps.Clone(s.opts)
	}
	if args != nil {
		s.args = args
	}
	s.depth++
	defer func() {
		s.depth--
		s.args = savedArgs
		s.leaving = false
		s.exiting = false
		if isolate {
			s.cwd, s.vars, s.exports, s.aliases = saved.cwd, saved.vars, saved.exports, saved.aliases
			s.traps, s.funcs, s.opts = savedTraps, savedFuncs, savedOpts
		}
	}()
	status = fn()
	if isolate && s.crashed {
		// This child shell died; its parent tells, as ash does.
		s.crashed, s.aborted = false, false
		fmt.Fprintln(s.errOrTerm(), "Segmentation fault")
		return 139, true
	}
	if isolate && len(s.traps) > 0 {
		s.runExitTrap(context.Background(), stdio{strings.NewReader(""), s.term, s.errOrTerm()})
	}
	return status, true
}

// runScript runs a script file in a child shell, with args as $0 $1 ...
func (s *Shell) runScript(ctx context.Context, p string, data []byte, args []string, std stdio) int {
	s.log.Event(audit.ExecScript, "path", p, "content", truncate(string(data), 4096))
	status, _ := s.nest(true, args, func() int { return s.execString(ctx, string(data), std) })
	return status
}

// commandSubst runs src in a child shell and returns its output without
// trailing newlines, as $(...) does.
func (s *Shell) commandSubst(ctx context.Context, src string) string {
	out := &limitedBuffer{max: maxCaptureBytes}
	stderr := s.errOut
	if stderr == nil {
		stderr = s.term
	}
	status, _ := s.nest(true, nil, func() int {
		return s.execString(ctx, src, stdio{strings.NewReader(""), out, stderr})
	})
	s.substRan, s.substCode = true, status
	return strings.TrimRight(out.String(), "\n")
}

// ashError words a filesystem error the way BusyBox ash does: it has its
// own text for a missing file, and uses strerror for the rest.
func ashError(err error, creating bool) string {
	if errors.Is(err, vfs.ErrNotExist) {
		if creating {
			return "nonexistent directory"
		}
		return "no such file"
	}
	return err.Error()
}

// isBusybox recognizes the BusyBox binary by its content, so copies of it
// work as it does on the device.
func isBusybox(data []byte) bool {
	return len(data) == busyboxSize && bytes.Contains(data[busyboxSize*3/4:], []byte("multi-call binary."))
}

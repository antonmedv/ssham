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

// Capture runs a line non-interactively and returns its combined output.
// It is used for `ssh host command` exec requests.
func (s *Shell) Capture(ctx context.Context, line string, stdin io.Reader) (output string, code int) {
	out := &limitedBuffer{max: maxCaptureBytes}
	defer func() {
		if r := recover(); r != nil {
			s.log.Event(audit.Panic, "line", line, "panic", fmt.Sprint(r))
			out.WriteString("Segmentation fault\n")
			output, code = out.String(), 139
		}
	}()
	code = s.execString(ctx, line, stdio{stdin, out, out})
	if s.exited {
		code = s.exitCode
	}
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
		if s.exited || s.leaving || s.jump != 0 || ctx.Err() != nil {
			break
		}
		skip := (prevOp == "&&" && s.status != 0) || (prevOp == "||" && s.status == 0)
		prevOp = l.ops[i]
		if skip {
			continue
		}
		if l.ops[i] == "&" {
			// Pretend to background the job; really run it, with no
			// terminal input so it cannot block.
			s.jobs++
			fmt.Fprintf(std.err, "[%d] %d\n", s.jobs, s.allocPID())
			s.runPipeline(ctx, pl, stdio{strings.NewReader(""), std.out, std.err})
			s.status = 0
			continue
		}
		s.status = s.runPipeline(ctx, pl, std)
	}
	if ctx.Err() != nil && s.depth == 0 {
		s.status = 130
	}
	return s.status
}

// runPipeline runs the commands one after another, feeding each one's
// output to the next. Commands are simulated, so there is no need for real
// concurrency.
func (s *Shell) runPipeline(ctx context.Context, pl *pipeline, std stdio) int {
	in := std.in
	status := 0
	for i, c := range pl.cmds {
		cio := stdio{in, std.out, std.err}
		var buf *limitedBuffer
		if i < len(pl.cmds)-1 {
			buf = &limitedBuffer{max: maxCaptureBytes}
			cio.out = buf
		}
		status = s.runCommand(ctx, c, cio)
		if buf != nil {
			in = bytes.NewReader(buf.Bytes())
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
	}

	// Plain assignments: X=1 Y=2
	if len(c.words) == 0 {
		for _, a := range c.assigns {
			name, val, _ := strings.Cut(a, "=")
			s.setVar(name, s.expandOne(ctx, val))
		}
		if !s.checkExpand(std.err) {
			return 2
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

// maxIterations bounds a loop. A loop that runs longer is treated as
// endless: it waits like a hung command, until Ctrl+C or disconnect,
// instead of burning CPU.
const maxIterations = 10000

func (s *Shell) runIf(ctx context.Context, c *ifClause, std stdio) int {
	for i, cond := range c.conds {
		s.runList(ctx, cond, std)
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
		s.runList(ctx, c.cond, std)
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
			s.cfg.Sleep(ctx, 24*time.Hour)
			return 130
		}
		if ctx.Err() != nil || s.exited || s.leaving || !next(i) || s.jump != 0 {
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
		target := s.expandOne(ctx, r.target)
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
		case "<<<":
			std.in = strings.NewReader(target + "\n")
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
	name := args[0]
	if strings.Contains(name, "/") {
		return s.runPath(ctx, args, std)
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
	if n, err := s.fs.Stat("root", p); err == nil && n.FakeSize == busyboxSize {
		return s.busybox(ctx, path.Base(args[0]), args, std)
	}
	data, _ := s.fs.ReadFile("root", p)
	if !bytes.HasPrefix(data, []byte("\x7fELF")) && isText(data) {
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
			s.log.Event(audit.Panic, "command", strings.Join(e.Args, " "), "panic", fmt.Sprint(r))
			fmt.Fprintln(e.Stderr, "Segmentation fault")
			status = 139
		}
	}()
	return run(e)
}

// nest runs fn one level deeper: in a script, sh -c, $(...), ( ... ) or a
// sourced file. exit inside it only ends that level. With isolate, it is a
// child shell: changes to the working directory, variables and aliases do
// not leak back to the parent. args, if not nil, become $0 $1 ...
// ok is false if the nesting limit was reached.
func (s *Shell) nest(isolate bool, args []string, fn func() int) (status int, ok bool) {
	if s.depth >= maxDepth {
		return 1, false
	}
	savedArgs := s.args
	var saved struct {
		cwd           string
		vars, aliases map[string]string
		exports       map[string]bool
	}
	if isolate {
		saved.cwd, saved.vars, saved.exports, saved.aliases = s.cwd, maps.Clone(s.vars), maps.Clone(s.exports), maps.Clone(s.aliases)
	}
	if args != nil {
		s.args = args
	}
	s.depth++
	defer func() {
		s.depth--
		s.args = savedArgs
		s.leaving = false
		if isolate {
			s.cwd, s.vars, s.exports, s.aliases = saved.cwd, saved.vars, saved.exports, saved.aliases
		}
	}()
	return fn(), true
}

// runScript runs a script file in a child shell, with args as $0 $1 ...
func (s *Shell) runScript(ctx context.Context, p string, data []byte, args []string, std stdio) int {
	s.log.Event(audit.ExecScript, "path", p, "content", truncate(string(data), 4096))
	status, ok := s.nest(true, args, func() int { return s.execString(ctx, string(data), std) })
	if !ok {
		fmt.Fprintf(std.err, "sh: %s: maximum nesting level exceeded\n", args[0])
	}
	return status
}

// commandSubst runs src in a child shell and returns its output without
// trailing newlines, as $(...) does.
func (s *Shell) commandSubst(ctx context.Context, src string) string {
	out := &limitedBuffer{max: maxCaptureBytes}
	s.nest(true, nil, func() int {
		return s.execString(ctx, src, stdio{strings.NewReader(""), out, s.term})
	})
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

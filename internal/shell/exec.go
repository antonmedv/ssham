package shell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"path"
	"strings"

	"github.com/antonmedv/ssham/internal/audit"
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
			s.write("Segmentation fault (core dumped)\n")
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
			out.WriteString("Segmentation fault (core dumped)\n")
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
		fmt.Fprintf(std.err, "-bash: %v\n", err)
		s.status = 2
		return s.status
	}
	return s.runList(ctx, l, std)
}

// runList runs commands joined by ; & && ||.
func (s *Shell) runList(ctx context.Context, l *list, std stdio) int {
	prevOp := ";"
	for i, pl := range l.items {
		if s.exited || s.leaving || ctx.Err() != nil {
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
	return status
}

func (s *Shell) runCommand(ctx context.Context, c *command, std stdio) int {
	if ctx.Err() != nil {
		return 130
	}
	std, flush, ok := s.redirect(ctx, c.redirs, std)
	defer flush()
	if !ok {
		return 1
	}

	if c.group != nil {
		// ( ... ) is a subshell.
		status, _ := s.nest(true, nil, func() int { return s.runList(ctx, c.group, std) })
		return status
	}

	// Plain assignments: X=1 Y=2
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
				fmt.Fprintf(std.err, "-bash: %s: ambiguous redirect\n", r.target)
				return std, flush, false
			}
			var w io.Writer
			if s.resolve(target) == "/dev/null" {
				w = io.Discard
			} else {
				f, err := s.openOutput(target, r.op == ">>" || r.op == "&>>", std.err)
				if err != nil {
					fmt.Fprintf(std.err, "-bash: %s: %s\n", target, err)
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
				fmt.Fprintf(std.err, "-bash: %s: %s\n", target, err)
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
		fmt.Fprintf(f.stderr, "-bash: %s: %s\n", f.name, err)
	}
}

// run dispatches argv to a builtin, a simulated program, or a script.
func (s *Shell) run(ctx context.Context, args []string, std stdio) int {
	name := args[0]
	if strings.Contains(name, "/") {
		return s.runPath(ctx, args, std)
	}
	if b, ok := builtins[name]; ok {
		return s.call(b.run, s.env(ctx, args, std))
	}
	if _, ok := s.lookPath(name); ok {
		return s.runProgram(ctx, name, args, std)
	}
	fmt.Fprintf(std.err, "%s: command not found\n", name)
	return 127
}

// runProgram runs an installed program by name.
func (s *Shell) runProgram(ctx context.Context, name string, args []string, std stdio) int {
	if c, ok := s.cfg.Commands.Lookup(name); ok {
		if c.Run == nil {
			return 0
		}
		return s.call(c.Run, s.env(ctx, args, std))
	}
	if b, ok := builtins[name]; ok && b.binary {
		return s.call(b.run, s.env(ctx, args, std))
	}
	return 0 // installed, but not simulated
}

// call runs a command, turning a panic (a bug in the simulation) into a
// crash of that one command, the way a segfault would look.
func (s *Shell) call(run func(*Env) int, e *Env) (status int) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Event(audit.Panic, "command", strings.Join(e.Args, " "), "panic", fmt.Sprint(r))
			fmt.Fprintln(e.Stderr, "Segmentation fault (core dumped)")
			status = 139
		}
	}()
	return run(e)
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

// runPath handles ./script.sh, /usr/bin/ls and friends.
func (s *Shell) runPath(ctx context.Context, args []string, std stdio) int {
	name := args[0]
	v := s.view()
	n, err := v.Stat(name)
	switch {
	case err != nil:
		fmt.Fprintf(std.err, "-bash: %s: %s\n", name, err)
		return 127
	case n.IsDir():
		fmt.Fprintf(std.err, "-bash: %s: Is a directory\n", name)
		return 126
	case !v.Can(n, vfs.Exec):
		fmt.Fprintf(std.err, "-bash: %s: Permission denied\n", name)
		return 126
	}
	p := v.Abs(name)
	if n.FakeSize > 0 {
		// A stock binary: run the simulation if it is one we know.
		return s.runProgram(ctx, path.Base(p), args, std)
	}
	data, _ := s.fs.ReadFile("root", p)
	if bytes.HasPrefix(data, []byte("\x7fELF")) || !isText(data) {
		// A dropped payload: pretend it crashed.
		s.log.Event(audit.ExecBinary, "path", p, "args", strings.Join(args[1:], " "))
		fmt.Fprintln(std.err, "Segmentation fault (core dumped)")
		return 139
	}
	return s.runScript(ctx, p, data, args, std)
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
		fmt.Fprintf(std.err, "-bash: %s: maximum nesting level exceeded\n", args[0])
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

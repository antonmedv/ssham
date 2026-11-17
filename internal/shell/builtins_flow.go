package shell

import (
	"strconv"
	"strings"
)

func builtinExit(e *Env) int {
	s := e.sh
	code := s.status
	if len(e.Args) > 1 {
		n, err := strconv.Atoi(e.Args[1])
		if err != nil {
			sh(e, "exit: Illegal number: %s", e.Args[1])
			return 2
		}
		code = n & 0xff
	}
	if s.funcDepth > 0 {
		// exit in a function leaves the shell the function runs in.
		s.exiting = true
	}
	if s.depth > 0 {
		// exit inside a script or subshell ends only that.
		s.leaving = true
		return code
	}
	if s.popIdentity() {
		return code // leave a nested shell
	}
	s.exited = true
	s.exitCode = code
	return code
}

// builtinReturn leaves a function or a sourced file.
func builtinReturn(e *Env) int {
	s := e.sh
	code := s.status
	if len(e.Args) > 1 {
		code, _ = strconv.Atoi(e.Args[1])
	}
	if s.depth == 0 {
		return code // ash ignores return at the top level
	}
	s.leaving = true
	return code & 0xff
}

// builtinBreak implements break and continue.
func builtinBreak(e *Env) int {
	s := e.sh
	n := 1
	if len(e.Args) > 1 {
		var err error
		if n, err = strconv.Atoi(e.Args[1]); err != nil || n < 1 {
			sh(e, "%s: Illegal number: %s", e.Args[0], e.Args[1])
			return 2
		}
	}
	if s.loopDepth == 0 {
		return 0 // outside a loop: ignored, as in ash
	}
	n = min(n, s.loopDepth)
	if e.Args[0] == "continue" {
		n = -n
	}
	s.jump = n
	return 0
}

func builtinSource(e *Env) int {
	if len(e.Args) < 2 {
		sh(e, "%s: filename argument required", e.Args[0])
		return 2
	}
	s := e.sh
	name := e.Args[1]
	p := name
	if !strings.Contains(name, "/") {
		// Like ash, look the file up in $PATH first.
		if found, ok := s.lookPath(name); ok {
			p = found
		}
	}
	data, err := e.FS.ReadFile(p)
	if err != nil {
		sh(e, "%s: can't open '%s'", e.Args[0], name)
		return 2
	}
	// A sourced file runs in the current shell, not a child.
	status, _ := s.nest(false, e.Args[1:], func() int { return s.execString(e.Ctx, string(data), e.io) })
	return status
}

func builtinEval(e *Env) int {
	return e.sh.execString(e.Ctx, strings.Join(e.Args[1:], " "), e.io)
}

func builtinExec(e *Env) int {
	if len(e.Args) < 2 {
		return 0
	}
	code := e.sh.run(e.Ctx, e.Args[1:], e.io)
	if e.sh.depth == 0 {
		// exec replaces the login shell: the session ends with it.
		e.sh.exited = true
		e.sh.exitCode = code
	}
	return code
}

func builtinCommand(e *Env) int {
	args := e.Args[1:]
	if len(args) > 0 && (args[0] == "-v" || args[0] == "-V") {
		if args[0] == "-V" {
			return builtinType(&Env{Ctx: e.Ctx, Args: append([]string{"type"}, args[1:]...), Stdin: e.Stdin, Stdout: e.Stdout, Stderr: e.Stderr, FS: e.FS, sh: e.sh, io: e.io})
		}
		status := 0
		for _, n := range args[1:] {
			if _, ok := builtins[n]; ok {
				e.Printf("%s\n", n)
			} else if p, ok := e.sh.lookPath(n); ok {
				e.Printf("%s\n", p)
			} else {
				status = 127
			}
		}
		return status
	}
	if len(args) == 0 {
		return 0
	}
	return e.sh.run(e.Ctx, args, e.io)
}

func builtinType(e *Env) int {
	s := e.sh
	status := 0
	for _, name := range e.Args[1:] {
		if a, ok := s.aliases[name]; ok {
			e.Printf("%s is an alias for %s\n", name, a)
		} else if _, ok := builtins[name]; ok {
			e.Printf("%s is a shell builtin\n", name)
		} else if reserved[name] {
			e.Printf("%s is a shell keyword\n", name)
		} else if p, ok := s.lookPath(name); ok {
			e.Printf("%s is %s\n", name, p)
		} else {
			e.Printf("%s: not found\n", name)
			status = 127
		}
	}
	return status
}

func builtinHistory(e *Env) int {
	for i, line := range e.sh.history {
		e.Printf("%4d %s\n", i, line)
	}
	return 0
}

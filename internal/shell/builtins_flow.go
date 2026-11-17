package shell

import (
	"fmt"
	"strconv"
	"strings"
)

func builtinExit(e *Env) int {
	s := e.sh
	code := s.status
	if len(e.Args) > 1 {
		if n, err := strconv.Atoi(e.Args[1]); err == nil {
			code = n & 0xff
		}
	}
	if s.depth > 0 {
		// exit inside a script or subshell ends only that.
		s.leaving = true
		return code
	}
	if s.popIdentity() {
		fmt.Fprintln(e.Stderr, "exit")
		return code
	}
	if e.Args[0] == "logout" || s.cfg.Term != "" {
		fmt.Fprintln(e.Stderr, "logout")
	}
	s.exited = true
	s.exitCode = code
	return code
}

func builtinSource(e *Env) int {
	if len(e.Args) < 2 {
		fmt.Fprintf(e.Stderr, "-bash: %s: filename argument required\n", e.Args[0])
		return 2
	}
	s := e.sh
	p := s.resolve(e.Args[1])
	data, err := e.FS.ReadFile(p)
	if err != nil {
		fmt.Fprintf(e.Stderr, "-bash: %s: %s\n", e.Args[1], err)
		return 1
	}
	// .bashrc returns early in non-interactive shells; skip it entirely
	// rather than interpreting case statements we do not support.
	if strings.HasSuffix(p, "/.bashrc") || strings.HasSuffix(p, "/.profile") {
		return 0
	}
	// A sourced file runs in the current shell, not a child.
	status, ok := s.nest(false, e.Args[1:], func() int { return s.execString(e.Ctx, string(data), e.io) })
	if !ok {
		fmt.Fprintf(e.Stderr, "-bash: %s: maximum nesting level exceeded\n", e.Args[1])
	}
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
	if e.sh.depth == 0 && !isShellName(e.Args[1]) {
		e.sh.exited = true
		e.sh.exitCode = code
	}
	return code
}

func builtinCommand(e *Env) int {
	args := e.Args[1:]
	if len(args) > 0 && args[0] == "-v" {
		status := 0
		for _, n := range args[1:] {
			if _, ok := builtins[n]; ok {
				e.Printf("%s\n", n)
			} else if p, ok := e.sh.lookPath(n); ok {
				e.Printf("%s\n", p)
			} else {
				status = 1
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
		if strings.HasPrefix(name, "-") {
			continue
		}
		if a, ok := s.aliases[name]; ok {
			e.Printf("%s is aliased to `%s'\n", name, a)
		} else if _, ok := builtins[name]; ok {
			e.Printf("%s is a shell builtin\n", name)
		} else if p, ok := s.lookPath(name); ok {
			e.Printf("%s is %s\n", name, p)
		} else {
			fmt.Fprintf(e.Stderr, "-bash: type: %s: not found\n", name)
			status = 1
		}
	}
	return status
}

func builtinHistory(e *Env) int {
	o := e.Flags()
	if o.Has("c") {
		e.sh.history = nil
		return 0
	}
	h := e.sh.history
	start := 0
	if len(o.Args) > 0 {
		if n, err := strconv.Atoi(o.Args[0]); err == nil && n < len(h) {
			start = len(h) - n
		}
	}
	for i := start; i < len(h); i++ {
		e.Printf("%5d  %s\n", i+1, h[i])
	}
	return 0
}

func isShellName(n string) bool {
	switch n[strings.LastIndexByte(n, '/')+1:] {
	case "sh", "bash", "dash", "zsh", "ash":
		return true
	}
	return false
}

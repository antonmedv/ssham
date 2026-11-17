package shell

import (
	"sort"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/audit"
)

// quote renders a value the way ash's set and export -p print it.
func quote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

// builtinExport implements export and readonly.
func builtinExport(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	if len(args) == 0 || (len(args) == 1 && args[0] == "-p") {
		for _, kv := range s.environ(true) {
			k, v, _ := strings.Cut(kv, "=")
			e.Printf("%s %s=%s\n", e.Args[0], k, quote(v))
		}
		return 0
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		if !isName(name) {
			sh(e, "%s: bad variable name", e.Args[0])
			return 2
		}
		if hasVal {
			s.vars[name] = val
		}
		s.exports[name] = true
	}
	return 0
}

func builtinUnset(e *Env) int {
	for _, a := range e.Args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		delete(e.sh.vars, a)
		delete(e.sh.exports, a)
	}
	return 0
}

func builtinAlias(e *Env) int {
	s := e.sh
	if len(e.Args) == 1 {
		names := make([]string, 0, len(s.aliases))
		for k := range s.aliases {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			e.Printf("%s=%s\n", k, quote(s.aliases[k]))
		}
		return 0
	}
	status := 0
	for _, a := range e.Args[1:] {
		name, val, ok := strings.Cut(a, "=")
		if !ok {
			if v, ok := s.aliases[name]; ok {
				e.Printf("%s=%s\n", name, quote(v))
			} else {
				sh(e, "alias: %s not found", name)
				status = 1
			}
			continue
		}
		s.aliases[name] = val
	}
	return status
}

func builtinUnalias(e *Env) int {
	for _, a := range e.Args[1:] {
		if a == "-a" {
			e.sh.aliases = map[string]string{}
			continue
		}
		if _, ok := e.sh.aliases[a]; !ok {
			sh(e, "unalias: %s not found", a)
			return 1
		}
		delete(e.sh.aliases, a)
	}
	return 0
}

// builtinSet prints all variables, as ash does with no arguments. Option
// flags are accepted and ignored; positional arguments replace $1 $2 ...
func builtinSet(e *Env) int {
	if len(e.Args) == 1 {
		for _, kv := range e.sh.environ(false) {
			k, v, _ := strings.Cut(kv, "=")
			e.Printf("%s=%s\n", k, quote(v))
		}
		return 0
	}
	args := e.Args[1:]
	if args[0] == "--" {
		args = args[1:]
	} else if strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[0], "+") {
		return 0
	}
	argv0 := "-sh"
	if len(e.sh.args) > 0 {
		argv0 = e.sh.args[0]
	}
	e.sh.args = append([]string{argv0}, args...)
	return 0
}

func builtinShift(e *Env) int {
	s := e.sh
	n := 1
	if len(e.Args) > 1 {
		n, _ = strconv.Atoi(e.Args[1])
	}
	if len(s.args) == 0 {
		s.args = []string{"-sh"}
	}
	if n > len(s.args)-1 {
		sh(e, "shift: can't shift that many")
		return 2
	}
	s.args = append(s.args[:1], s.args[1+n:]...)
	return 0
}

// builtinLet evaluates each argument as arithmetic; it fails if the last
// one is zero.
func builtinLet(e *Env) int {
	if len(e.Args) < 2 {
		sh(e, "let: expression expected")
		return 1
	}
	var v int64
	for _, expr := range e.Args[1:] {
		name, rhs, assign := strings.Cut(expr, "=")
		var err error
		if assign && isName(name) && !strings.HasPrefix(rhs, "=") {
			v, err = arith(rhs, e.sh.getVar)
			e.sh.setVar(name, strconv.FormatInt(v, 10))
		} else {
			v, err = arith(expr, e.sh.getVar)
		}
		if err != nil {
			sh(e, "let: %s", err)
			return 2
		}
	}
	if v == 0 {
		return 1
	}
	return 0
}

// builtinLocal fails: functions are not supported, and ash only allows
// local inside one.
func builtinLocal(e *Env) int {
	sh(e, "local: not in a function")
	return 2
}

func builtinRead(e *Env) int {
	o := e.Flags("p", "t", "n", "d", "u")
	prompt, _ := o.Value("p")
	line, err := e.ReadLine(prompt, !o.Has("s"))
	if err != nil {
		return 1
	}
	if e.Interactive() {
		e.Log(audit.Stdin, "line", line)
	}
	names := o.Args
	if len(names) == 0 {
		names = []string{"REPLY"}
	}
	fields := strings.Fields(line)
	for i, n := range names {
		switch {
		case i == len(names)-1 && i < len(fields):
			e.sh.vars[n] = strings.Join(fields[i:], " ")
		case i < len(fields):
			e.sh.vars[n] = fields[i]
		default:
			e.sh.vars[n] = ""
		}
	}
	return 0
}

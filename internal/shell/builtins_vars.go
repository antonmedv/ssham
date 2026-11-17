package shell

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antonmedv/ssham/internal/audit"
)

func builtinExport(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	if len(args) == 0 || (len(args) == 1 && args[0] == "-p") {
		for _, kv := range s.environ(true) {
			k, v, _ := strings.Cut(kv, "=")
			e.Printf("declare -x %s=%q\n", k, v)
		}
		return 0
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		if !isName(name) {
			fmt.Fprintf(e.Stderr, "-bash: export: `%s': not a valid identifier\n", a)
			return 1
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
			e.Printf("alias %s='%s'\n", k, s.aliases[k])
		}
		return 0
	}
	status := 0
	for _, a := range e.Args[1:] {
		name, val, ok := strings.Cut(a, "=")
		if !ok {
			if v, ok := s.aliases[name]; ok {
				e.Printf("alias %s='%s'\n", name, v)
			} else {
				fmt.Fprintf(e.Stderr, "-bash: alias: %s: not found\n", name)
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
		delete(e.sh.aliases, a)
	}
	return 0
}

func builtinSet(e *Env) int {
	if len(e.Args) == 1 {
		for _, kv := range e.sh.environ(false) {
			e.Printf("%s\n", kv)
		}
	}
	return 0
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

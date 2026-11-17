package shell

import (
	"context"
	"strings"
)

// Functions, case, here-documents and local variables.

// specialBuiltins run even when a function has the same name, as in ash.
var specialBuiltins = map[string]bool{
	"break": true, ":": true, "continue": true, ".": true, "eval": true, "exec": true,
	"exit": true, "export": true, "readonly": true, "return": true, "set": true,
	"shift": true, "trap": true, "unset": true,
}

// callFunction runs a function with args as $1 $2 ...; $0 stays.
func (s *Shell) callFunction(ctx context.Context, body *command, args []string, std stdio) int {
	if !s.step() {
		return 130
	}
	arg0 := "-sh"
	if len(s.args) > 0 {
		arg0 = s.args[0]
	} else if s.cfg.Mode == RunCommand {
		arg0 = "sh"
	}
	s.locals = append(s.locals, map[string]*string{})
	s.funcDepth++
	defer func() {
		s.funcDepth--
		frame := s.locals[len(s.locals)-1]
		s.locals = s.locals[:len(s.locals)-1]
		for name, old := range frame {
			if old == nil {
				delete(s.vars, name)
			} else {
				s.vars[name] = *old
			}
		}
	}()
	status, _ := s.nestFunc(append([]string{arg0}, args[1:]...), func() int { return s.runCommand(ctx, body, std) })
	return status
}

// nestFunc is nest for a function call: no new process, and an exit in
// the function leaves the whole shell.
func (s *Shell) nestFunc(args []string, fn func() int) (int, bool) {
	if s.depth >= maxDepth {
		s.overflow()
		return 139, false
	}
	saved := s.args
	s.args = args
	s.depth++
	defer func() {
		s.depth--
		s.args = saved
		if !s.exiting {
			s.leaving = false // return ends only the function
		}
	}()
	return fn(), true
}

func builtinLocal(e *Env) int {
	s := e.sh
	if len(s.locals) == 0 {
		sh(e, "local: not in a function")
		return 2
	}
	frame := s.locals[len(s.locals)-1]
	for _, a := range e.Args[1:] {
		name, val, hasVal := strings.Cut(a, "=")
		if !isName(name) {
			sh(e, "local: %s: bad variable name", name)
			return 2
		}
		if _, saved := frame[name]; !saved {
			if old, ok := s.vars[name]; ok {
				frame[name] = &old
			} else {
				frame[name] = nil
			}
		}
		if hasVal {
			s.vars[name] = val
		}
	}
	return 0
}

func (s *Shell) runCase(ctx context.Context, c *caseClause, std stdio) int {
	word := s.expandOne(ctx, c.word)
	for _, item := range c.items {
		for _, p := range item.patterns {
			re := patternRegexp(s.expandPattern(ctx, p))
			if re != nil && re.MatchString(word) {
				return s.runList(ctx, item.body, std)
			}
		}
	}
	return 0
}

// expandPattern expands a case pattern: quoted parts match literally.
func (s *Shell) expandPattern(ctx context.Context, raw string) string {
	e := &expander{sh: s, ctx: ctx}
	for i := 0; i < len(raw); {
		switch c := raw[i]; c {
		case '*', '?', '[', ']':
			e.addGlobChar(c)
			i++
		case '\\':
			if i+1 < len(raw) {
				e.addLit(raw[i+1:i+2], true)
			}
			i += 2
		case '\'', '"', '$', '`':
			n, err := skipQuoted(raw[i:])
			if err != nil || n == 0 {
				n = len(raw) - i
			}
			for _, v := range s.expandWord(ctx, raw[i:i+n], false) {
				e.addLit(v, true)
			}
			i += n
		default:
			e.addLit(string(c), false)
			i++
		}
	}
	e.endField()
	if len(e.fields) == 0 {
		return ""
	}
	return e.fields[0].pat.String()
}

// heredocText is what a here-document feeds to stdin: the body, with
// $var, $(...) and `...` expanded unless the delimiter was quoted.
func (s *Shell) heredocText(ctx context.Context, d *heredoc) string {
	if d.quoted {
		return d.body
	}
	// Inside a here-document only \$ \` \\ and \newline are escapes, as
	// inside double quotes, but " is an ordinary character.
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(d.body); i++ {
		c := d.body[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\' && i+1 < len(d.body) && d.body[i+1] == '"':
			b.WriteString(`\\\"`)
			i++
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return s.expandOne(ctx, b.String())
}

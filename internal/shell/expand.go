package shell

import (
	"context"
	"path"
	"sort"
	"strconv"
	"strings"
)

// field is one word being built during expansion. lit is the final text;
// pat is the same text with glob metacharacters escaped where they were
// quoted, so only unquoted * ? [ act as wildcards.
type field struct {
	lit, pat strings.Builder
	quoted   bool // contains a quoted part, so it survives even if empty
	glob     bool // contains an unquoted wildcard
	started  bool
}

type expander struct {
	sh     *Shell
	ctx    context.Context
	fields []*field
	cur    *field
}

func (e *expander) field() *field {
	if e.cur == nil {
		e.cur = &field{}
	}
	e.cur.started = true
	return e.cur
}

func (e *expander) endField() {
	if e.cur != nil && e.cur.started {
		e.fields = append(e.fields, e.cur)
	}
	e.cur = nil
}

func (e *expander) addLit(s string, quoted bool) {
	f := e.field()
	f.lit.WriteString(s)
	if quoted {
		f.quoted = true
		for _, r := range s {
			if strings.ContainsRune(`*?[]\`, r) {
				f.pat.WriteByte('\\')
			}
			f.pat.WriteRune(r)
		}
		return
	}
	for _, r := range s {
		if r == '\\' {
			f.pat.WriteByte('\\')
		}
		f.pat.WriteRune(r)
	}
}

func (e *expander) addGlobChar(c byte) {
	f := e.field()
	f.lit.WriteByte(c)
	f.pat.WriteByte(c)
	f.glob = true
}

// addSplit adds the result of an unquoted expansion, splitting it into
// separate fields on whitespace the way bash does with the default IFS.
func (e *expander) addSplit(s string) {
	if s == "" {
		return
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		e.endField()
		return
	}
	if strings.IndexAny(s[:1], " \t\n") == 0 {
		e.endField()
	}
	for i, p := range parts {
		if i > 0 {
			e.endField()
		}
		e.addLit(p, true)
		e.cur.quoted = false
	}
	if strings.ContainsAny(s[len(s)-1:], " \t\n") {
		e.endField()
	}
}

// expandWords expands raw words into argv.
func (s *Shell) expandWords(ctx context.Context, words []string) []string {
	var out []string
	for _, w := range words {
		out = append(out, s.expandWord(ctx, w, true)...)
	}
	return out
}

// expandOne expands a word without field splitting or globbing, as used for
// assignments and redirection targets.
func (s *Shell) expandOne(ctx context.Context, w string) string {
	return strings.Join(s.expandWord(ctx, w, false), " ")
}

func (s *Shell) expandWord(ctx context.Context, raw string, split bool) []string {
	e := &expander{sh: s, ctx: ctx}
	i := 0
	// Tilde expansion at the start of a word.
	if strings.HasPrefix(raw, "~") {
		end := strings.IndexByte(raw, '/')
		if end < 0 {
			end = len(raw)
		}
		switch name := raw[1:end]; name {
		case "":
			e.addLit(s.getVar("HOME"), true)
			i = end
		case "root":
			e.addLit("/root", true)
			i = end
		case s.user.Name:
			e.addLit(s.user.Home, true)
			i = end
		}
	}
	for i < len(raw) {
		c := raw[i]
		switch c {
		case '\\':
			if i+1 < len(raw) {
				e.addLit(raw[i+1:i+2], true)
				i += 2
			} else {
				i++
			}
		case '\'':
			end := strings.IndexByte(raw[i+1:], '\'')
			if end < 0 {
				end = len(raw) - i - 1
			}
			e.addLit(raw[i+1:i+1+end], true)
			i += end + 2
		case '"':
			i = e.doubleQuoted(raw, i+1)
		case '$':
			val, n, _ := e.dollar(raw[i:])
			i += n
			if split {
				e.addSplit(val)
			} else {
				e.addLit(val, true)
			}
		case '`':
			end := strings.IndexByte(raw[i+1:], '`')
			if end < 0 {
				end = len(raw) - i - 1
			}
			val := s.commandSubst(ctx, raw[i+1:i+1+end])
			if split {
				e.addSplit(val)
			} else {
				e.addLit(val, true)
			}
			i += end + 2
		case '*', '?', '[':
			if split {
				e.addGlobChar(c)
			} else {
				e.addLit(string(c), false)
			}
			i++
		default:
			e.addLit(string(c), false)
			i++
		}
	}
	e.endField()

	var out []string
	for _, f := range e.fields {
		if f.glob {
			if matches := s.glob(f.pat.String()); len(matches) > 0 {
				out = append(out, matches...)
				continue
			}
		}
		if f.lit.Len() == 0 && !f.quoted {
			continue
		}
		out = append(out, f.lit.String())
	}
	if !split && len(out) == 0 {
		out = []string{""}
	}
	return out
}

// doubleQuoted handles text inside "..." starting at raw[i] and returns the
// index just past the closing quote.
func (e *expander) doubleQuoted(raw string, i int) int {
	e.field().quoted = true
	for i < len(raw) {
		c := raw[i]
		switch c {
		case '"':
			return i + 1
		case '\\':
			if i+1 < len(raw) && strings.IndexByte("$`\"\\\n", raw[i+1]) >= 0 {
				e.addLit(raw[i+1:i+2], true)
				i += 2
				continue
			}
			e.addLit("\\", true)
			i++
		case '$':
			val, n, _ := e.dollar(raw[i:])
			e.addLit(val, true)
			i += n
		case '`':
			end := strings.IndexByte(raw[i+1:], '`')
			if end < 0 {
				end = len(raw) - i - 1
			}
			e.addLit(e.sh.commandSubst(e.ctx, raw[i+1:i+1+end]), true)
			i += end + 2
		default:
			e.addLit(string(c), true)
			i++
		}
	}
	return i
}

// dollar expands a $-expression at the start of s. It returns the value,
// the number of bytes consumed, and whether it was a command substitution.
func (e *expander) dollar(s string) (string, int, bool) {
	sh := e.sh
	if len(s) < 2 {
		return "$", 1, false
	}
	switch c := s[1]; {
	case c == '(':
		if strings.HasPrefix(s, "$((") {
			end := strings.Index(s, "))")
			if end > 0 {
				return strconv.FormatInt(arith(sh.expandOne(e.ctx, s[3:end]), sh.getVar), 10), end + 2, false
			}
		}
		n, err := skipQuoted(s)
		if err != nil {
			n = len(s)
		}
		inner := s[2:max(2, n-1)]
		return sh.commandSubst(e.ctx, inner), n, true
	case c == '{':
		end := strings.IndexByte(s, '}')
		if end < 0 {
			return s, len(s), false
		}
		expr := s[2:end]
		if strings.HasPrefix(expr, "#") && isName(expr[1:]) {
			return strconv.Itoa(len(sh.getVar(expr[1:]))), end + 1, false
		}
		for _, op := range []string{":-", ":=", ":+", "-"} {
			if name, def, ok := strings.Cut(expr, op); ok && isName(name) {
				v := sh.getVar(name)
				switch op {
				case ":-", "-":
					if v == "" {
						v = sh.expandOne(e.ctx, def)
					}
				case ":=":
					if v == "" {
						v = sh.expandOne(e.ctx, def)
						sh.setVar(name, v)
					}
				case ":+":
					if v != "" {
						v = sh.expandOne(e.ctx, def)
					}
				}
				return v, end + 1, false
			}
		}
		return sh.getVar(expr), end + 1, false
	case c == '?':
		return strconv.Itoa(sh.status), 2, false
	case c == '$':
		return strconv.Itoa(sh.pid), 2, false
	case c == '#':
		return strconv.Itoa(max(0, len(sh.args)-1)), 2, false
	case c == '@' || c == '*':
		if len(sh.args) > 1 {
			return strings.Join(sh.args[1:], " "), 2, false
		}
		return "", 2, false
	case c == '-':
		return "himBHs", 2, false
	case c == '!':
		return "", 2, false
	case c >= '0' && c <= '9':
		idx := int(c - '0')
		if idx < len(sh.args) {
			return sh.args[idx], 2, false
		}
		if idx == 0 {
			return "-bash", 2, false
		}
		return "", 2, false
	case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		j := 2
		for j < len(s) && (s[j] == '_' || (s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= '0' && s[j] <= '9')) {
			j++
		}
		return sh.getVar(s[1:j]), j, false
	}
	return "$", 1, false
}

// glob expands a pattern against the virtual filesystem.
func (s *Shell) glob(pat string) []string {
	abs := strings.HasPrefix(pat, "/")
	parts := strings.Split(strings.Trim(pat, "/"), "/")
	bases := []string{""}
	if abs {
		bases = []string{"/"}
	}
	for _, part := range parts {
		var next []string
		hasMeta := strings.ContainsAny(part, "*?[")
		for _, b := range bases {
			dir := b
			if dir == "" {
				dir = s.cwd
			} else {
				dir = s.resolve(dir)
			}
			if !hasMeta {
				lit := unescapeGlob(part)
				cand := joinGlob(b, lit)
				if _, err := s.fs.Lstat(s.user.Name, s.resolve(cand)); err == nil {
					next = append(next, cand)
				}
				continue
			}
			entries, err := s.fs.ReadDir(s.user.Name, dir)
			if err != nil {
				continue
			}
			for _, ent := range entries {
				if strings.HasPrefix(ent.Name, ".") && !strings.HasPrefix(part, ".") {
					continue
				}
				if ok, _ := path.Match(part, ent.Name); ok {
					next = append(next, joinGlob(b, ent.Name))
				}
			}
		}
		bases = next
		if len(bases) == 0 {
			return nil
		}
	}
	sort.Strings(bases)
	return bases
}

func joinGlob(base, name string) string {
	switch base {
	case "":
		return name
	case "/":
		return "/" + name
	}
	return base + "/" + name
}

func unescapeGlob(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

package shell

import (
	"context"
	"path"
	"regexp"
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
	if split && (raw == `"$@"` || raw == `"${@}"`) {
		// Each argument is a field of its own; none at all if there are
		// none.
		if len(s.args) > 1 {
			return append([]string(nil), s.args[1:]...)
		}
		return nil
	}
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
			if strings.HasPrefix(raw[i:], "$'") {
				// $'...': C escapes, from ash's bash extensions.
				n, err := skipQuoted(raw[i:])
				if err != nil || n < 2 {
					n = len(raw) - i
				}
				body := raw[i+2 : max(i+2, i+n-1)]
				lit, _ := Unescape(strings.ReplaceAll(body, `\'`, "'"))
				e.addLit(lit, true)
				i += n
				continue
			}
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
				v, err := arith(sh.expandOne(e.ctx, s[3:end]), sh.getVar, sh.setVar)
				if err != nil {
					sh.expandError(err.Error())
				}
				return strconv.FormatInt(v, 10), end + 2, false
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
		return e.braced(s[2:end]), end + 1, false
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
		return sh.flags(), 2, false
	case c == '!':
		if sh.lastBg == 0 {
			return "", 2, false
		}
		return strconv.Itoa(sh.lastBg), 2, false
	case c >= '0' && c <= '9':
		idx := int(c - '0')
		if idx < len(sh.args) {
			return sh.args[idx], 2, false
		}
		if idx == 0 {
			if sh.cfg.Mode == RunCommand {
				return "sh", 2, false
			}
			return "-sh", 2, false
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

// braced expands the forms ash supports inside ${...}. Anything else is a
// "bad substitution", as in ash: arrays, ${var/x/y}, ${!var}, ...
func (e *expander) braced(expr string) string {
	sh := e.sh
	param := func(name string) (string, bool) {
		switch {
		case name == "?" || name == "$" || name == "#" || name == "@" || name == "*" || name == "-" || (len(name) == 1 && name[0] >= '0' && name[0] <= '9'):
			v, _, _ := e.dollar("$" + name)
			return v, true
		case isName(name):
			_, set := sh.vars[name]
			return sh.getVar(name), set || name == "PPID"
		}
		return "", false
	}
	if expr == "#" {
		v, _ := param("#")
		return v
	}
	if rest, ok := strings.CutPrefix(expr, "#"); ok {
		if !isName(rest) && !(len(rest) == 1 && strings.ContainsAny(rest, "0123456789@*")) {
			sh.expandError("syntax error: bad substitution")
			return ""
		}
		v, _ := param(rest)
		return strconv.Itoa(len(v))
	}
	// Split into name and operator.
	i := 0
	for i < len(expr) && (expr[i] == '_' || (expr[i] >= 'a' && expr[i] <= 'z') || (expr[i] >= 'A' && expr[i] <= 'Z') || (i > 0 && expr[i] >= '0' && expr[i] <= '9')) {
		i++
	}
	if i == 0 && len(expr) > 0 && strings.ContainsRune("?$#@*-0123456789", rune(expr[0])) {
		i = 1
	}
	name, op := expr[:i], expr[i:]
	if name == "" {
		sh.expandError("syntax error: bad substitution")
		return ""
	}
	v, set := param(name)
	word := func(prefix string) string { return sh.expandOne(e.ctx, strings.TrimPrefix(op, prefix)) }
	switch {
	case op == "":
		return v
	case strings.HasPrefix(op, ":-"):
		if v == "" {
			return word(":-")
		}
	case strings.HasPrefix(op, "-"):
		if !set {
			return word("-")
		}
	case strings.HasPrefix(op, ":="), strings.HasPrefix(op, "="):
		if v == "" && (op[0] == ':' || !set) {
			v = word(op[:strings.IndexByte(op, '=')+1])
			sh.setVar(name, v)
		}
	case strings.HasPrefix(op, ":+"):
		if v != "" {
			return word(":+")
		}
		return ""
	case strings.HasPrefix(op, "+"):
		if set {
			return word("+")
		}
		return ""
	case strings.HasPrefix(op, ":?"), strings.HasPrefix(op, "?"):
		if v == "" {
			msg := word(op[:strings.IndexByte(op, '?')+1])
			if msg == "" {
				msg = "parameter not set"
			}
			sh.expandError(name + ": " + msg)
		}
	case strings.HasPrefix(op, ":"):
		// ${x:offset} and ${x:offset:length}, from ash's bash extensions.
		offExpr, lenExpr, hasLen := strings.Cut(op[1:], ":")
		off, err := arith(offExpr, sh.getVar, sh.setVar)
		if err != nil {
			sh.expandError(err.Error())
			return ""
		}
		if off < 0 {
			off = max(0, int64(len(v))+off)
		}
		off = min(off, int64(len(v)))
		end := int64(len(v))
		if hasLen {
			n, err := arith(lenExpr, sh.getVar, sh.setVar)
			if err != nil {
				sh.expandError(err.Error())
				return ""
			}
			if n < 0 {
				end = max(off, end+n)
			} else {
				end = min(end, off+n)
			}
		}
		return v[off:end]
	case strings.HasPrefix(op, "/"):
		// ${x/pat/rep}, ${x//pat/rep}, ${x/#pat/rep}, ${x/%pat/rep}.
		mode := ""
		rest := op[1:]
		if len(rest) > 0 && strings.ContainsRune("/#%", rune(rest[0])) {
			mode, rest = rest[:1], rest[1:]
		}
		pat, rep, _ := strings.Cut(rest, "/")
		return replacePattern(v, sh.expandOne(e.ctx, pat), sh.expandOne(e.ctx, rep), mode)
	case strings.HasPrefix(op, "##"), strings.HasPrefix(op, "#"):
		return trimPattern(v, word(op[:strings.LastIndexByte(op[:min(2, len(op))], '#')+1]), true, op[:min(2, len(op))] == "##")
	case strings.HasPrefix(op, "%%"), strings.HasPrefix(op, "%"):
		return trimPattern(v, word(op[:strings.LastIndexByte(op[:min(2, len(op))], '%')+1]), false, op[:min(2, len(op))] == "%%")
	default:
		sh.expandError("syntax error: bad substitution")
		return ""
	}
	return v
}

// replacePattern replaces the longest match of pattern in v: the first
// one, every one (mode "/"), or only at the start ("#") or end ("%").
func replacePattern(v, pattern, rep, mode string) string {
	if pattern == "" {
		return v
	}
	re := patternRegexp(pattern)
	if re == nil {
		return v
	}
	match := func(s string) bool { return re.MatchString(s) }
	switch mode {
	case "#":
		for j := len(v); j >= 0; j-- {
			if match(v[:j]) {
				return rep + v[j:]
			}
		}
		return v
	case "%":
		for i := 0; i <= len(v); i++ {
			if match(v[i:]) {
				return v[:i] + rep
			}
		}
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); {
		found := -1
		for j := len(v); j > i; j-- {
			if match(v[i:j]) {
				found = j
				break
			}
		}
		if found < 0 {
			b.WriteByte(v[i])
			i++
			continue
		}
		b.WriteString(rep)
		i = found
		if mode != "/" {
			b.WriteString(v[i:])
			return b.String()
		}
	}
	return b.String()
}

// trimPattern removes the shortest (or longest) prefix or suffix of v
// matching the glob pattern, as ${v#pat}, ${v##pat}, ${v%pat} and ${v%%pat}.
func trimPattern(v, pattern string, prefix, longest bool) string {
	re := patternRegexp(pattern)
	match := func(s string) bool { return re != nil && re.MatchString(s) }
	if prefix {
		for i := 0; i <= len(v); i++ {
			j := i
			if longest {
				j = len(v) - i
			}
			if match(v[:j]) {
				return v[j:]
			}
		}
		return v
	}
	for i := 0; i <= len(v); i++ {
		j := len(v) - i
		if longest {
			j = i
		}
		if match(v[j:]) {
			return v[:j]
		}
	}
	return v
}

// patternRegexp compiles a shell pattern, where * and ? match any
// character including /, unlike in path.Match.
func patternRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			b.WriteString("(?s:.*)")
		case '?':
			b.WriteString("(?s:.)")
		case '[':
			if end := strings.IndexByte(pattern[i+1:], ']'); end >= 0 {
				class := pattern[i+1 : i+1+end]
				if strings.HasPrefix(class, "!") {
					class = "^" + class[1:]
				}
				b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
				i += end + 1
				continue
			}
			b.WriteString(regexp.QuoteMeta("["))
		case '\\':
			if i+1 < len(pattern) {
				i++
				b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
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

// flags is $-, the shell's option letters.
func (sh *Shell) flags() string {
	var b strings.Builder
	for _, f := range "efuvxnaCb" {
		if sh.opts[byte(f)] {
			b.WriteRune(f)
		}
	}
	switch sh.cfg.Mode {
	case LoginShell:
		b.WriteString("smi")
	case PipedShell:
		b.WriteString("s")
	}
	return b.String()
}

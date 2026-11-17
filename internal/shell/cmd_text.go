package shell

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// input returns the concatenated contents of the named files, or stdin if
// there are none. Errors are reported to stderr.
func (e *Env) input(files []string) (string, int) {
	if len(files) == 0 {
		return e.ReadStdin(), 0
	}
	var b strings.Builder
	status := 0
	for _, f := range files {
		if f == "-" {
			b.WriteString(e.ReadStdin())
			continue
		}
		data, err := e.sh.fs.ReadFile(e.sh.user, e.sh.resolve(f))
		if err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
			continue
		}
		b.Write(data)
	}
	return b.String(), status
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// countArg handles head/tail's -n N, -N and -n +N forms.
func countArg(args []string) (n int, from bool, rest []string) {
	n = 10
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" || a == "-c" || a == "--lines":
			if i+1 < len(args) {
				i++
				v := args[i]
				from = strings.HasPrefix(v, "+")
				n, _ = strconv.Atoi(strings.TrimPrefix(v, "+"))
			}
		case strings.HasPrefix(a, "-n"):
			v := a[2:]
			from = strings.HasPrefix(v, "+")
			n, _ = strconv.Atoi(strings.TrimPrefix(v, "+"))
		case strings.HasPrefix(a, "--lines="):
			n, _ = strconv.Atoi(a[8:])
		case len(a) > 1 && a[0] == '-' && a[1] >= '0' && a[1] <= '9':
			n, _ = strconv.Atoi(a[1:])
		case strings.HasPrefix(a, "-") && a != "-":
			// ignore other flags such as -q, -f
		default:
			rest = append(rest, a)
		}
	}
	return n, from, rest
}

func cmdHead(e *Env) int {
	n, _, files := countArg(e.Args[1:])
	data, status := e.input(files)
	lines := splitLines(data)
	if n < len(lines) {
		lines = lines[:n]
	}
	for _, l := range lines {
		e.Printf("%s\n", l)
	}
	return status
}

func cmdTail(e *Env) int {
	n, from, files := countArg(e.Args[1:])
	data, status := e.input(files)
	lines := splitLines(data)
	switch {
	case from:
		if n > 0 && n-1 < len(lines) {
			lines = lines[n-1:]
		} else if n-1 >= len(lines) {
			lines = nil
		}
	case n < len(lines):
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		e.Printf("%s\n", l)
	}
	return status
}

func cmdWc(e *Env) int {
	o := getopt(e.Args[1:])
	count := func(s string) (int, int, int) {
		return strings.Count(s, "\n"), len(strings.Fields(s)), len(s)
	}
	show := func(l, w, c int, name string) {
		var parts []string
		all := !o.has("l", "w", "c", "m", "lines", "words", "bytes", "chars")
		if all || o.has("l", "lines") {
			parts = append(parts, strconv.Itoa(l))
		}
		if all || o.has("w", "words") {
			parts = append(parts, strconv.Itoa(w))
		}
		if all || o.has("c", "m", "bytes", "chars") {
			parts = append(parts, strconv.Itoa(c))
		}
		if name != "" {
			parts = append(parts, name)
		}
		if all && name != "" {
			e.Printf("%3s %3s %3s %s\n", parts[0], parts[1], parts[2], name)
			return
		}
		e.Printf("%s\n", strings.Join(parts, " "))
	}
	if len(o.pos) == 0 {
		l, w, c := count(e.ReadStdin())
		show(l, w, c, "")
		return 0
	}
	status := 0
	var tl, tw, tc int
	for _, f := range o.pos {
		data, err := e.sh.fs.ReadFile(e.sh.user, e.sh.resolve(f))
		if err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
			continue
		}
		l, w, c := count(string(data))
		tl, tw, tc = tl+l, tw+w, tc+c
		show(l, w, c, f)
	}
	if len(o.pos) > 1 {
		show(tl, tw, tc, "total")
	}
	return status
}

func cmdGrep(e *Env) int {
	o := getopt(e.Args[1:], "e", "m", "A", "B", "C", "color", "colour", "max-count", "regexp")
	pats := []string{}
	if v, ok := o.val("e", "regexp"); ok {
		pats = append(pats, v)
	}
	files := o.pos
	if len(pats) == 0 {
		if len(files) == 0 {
			fmt.Fprintln(e.Stderr, "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.")
			return 2
		}
		pats = append(pats, strings.Split(files[0], "\n")...)
		files = files[1:]
	}
	expr := ""
	for i, p := range pats {
		if o.has("F", "fixed-strings") {
			p = regexp.QuoteMeta(p)
		} else if !o.has("E", "P", "extended-regexp") || e.Args[0] == "egrep" {
			// Basic regex: \| \( \) are operators, bare | ( ) are literal.
			p = basicToExtended(p)
		}
		if o.has("w", "word-regexp") {
			p = `\b(?:` + p + `)\b`
		}
		if o.has("x", "line-regexp") {
			p = `^(?:` + p + `)$`
		}
		if i > 0 {
			expr += "|"
		}
		expr += "(?:" + p + ")"
	}
	if o.has("i", "ignore-case") {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		fmt.Fprintf(e.Stderr, "grep: Invalid regular expression\n")
		return 2
	}
	invert := o.has("v", "invert-match")
	maxCount := -1
	if v, ok := o.val("m", "max-count"); ok {
		maxCount, _ = strconv.Atoi(v)
	}
	color := e.color()
	if c, ok := o.val("color", "colour"); ok {
		color = c == "always" || (c == "auto" && e.color())
	} else {
		color = false
	}
	recursive := o.has("r", "R", "recursive")
	if recursive && len(files) == 0 {
		files = []string{"."}
	}
	if recursive {
		var expanded []string
		for _, f := range files {
			expanded = append(expanded, walkFiles(e, f)...)
		}
		files = expanded
	}
	showName := (len(files) > 1 || recursive) && !o.has("h", "no-filename")
	if o.has("H", "with-filename") {
		showName = true
	}
	matched := false
	status := 0
	grepText := func(name, data string) {
		count := 0
		for i, line := range splitLines(data) {
			if maxCount >= 0 && count >= maxCount {
				break
			}
			if re.MatchString(line) == invert {
				continue
			}
			count++
			matched = true
			if o.has("q", "quiet", "silent", "c", "count", "l", "files-with-matches") {
				continue
			}
			out := line
			if o.has("o", "only-matching") && !invert {
				for _, m := range re.FindAllString(line, -1) {
					if showName {
						e.Printf("%s:", name)
					}
					e.Printf("%s\n", m)
				}
				continue
			}
			if color && !invert {
				out = re.ReplaceAllStringFunc(line, func(m string) string { return "\x1b[01;31m\x1b[K" + m + "\x1b[m\x1b[K" })
			}
			prefix := ""
			if showName {
				prefix = name + ":"
				if color {
					prefix = "\x1b[35m\x1b[K" + name + "\x1b[m\x1b[K\x1b[36m\x1b[K:\x1b[m\x1b[K"
				}
			}
			if o.has("n", "line-number") {
				prefix += strconv.Itoa(i+1) + ":"
			}
			e.Printf("%s%s\n", prefix, out)
		}
		if o.has("c", "count") {
			if showName {
				e.Printf("%s:", name)
			}
			e.Printf("%d\n", count)
		}
		if o.has("l", "files-with-matches") && count > 0 {
			e.Printf("%s\n", name)
		}
	}
	if len(files) == 0 {
		grepText("(standard input)", e.ReadStdin())
	}
	for _, f := range files {
		n, err := e.sh.fs.Stat(e.sh.user, e.sh.resolve(f))
		if err == nil && n.IsDir() {
			if !o.has("s", "no-messages") {
				fmt.Fprintf(e.Stderr, "grep: %s: Is a directory\n", f)
			}
			continue
		}
		data, err := e.sh.fs.ReadFile(e.sh.user, e.sh.resolve(f))
		if err != nil {
			if !o.has("s", "no-messages") {
				fmt.Fprintf(e.Stderr, "grep: %s: %s\n", f, err)
			}
			status = 2
			continue
		}
		grepText(f, string(data))
	}
	if status != 0 && !matched {
		return status
	}
	if !matched {
		return 1
	}
	return 0
}

func basicToExtended(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			switch p[i+1] {
			case '|', '(', ')', '{', '}', '+', '?':
				b.WriteByte(p[i+1])
				i++
				continue
			}
			b.WriteByte(c)
			b.WriteByte(p[i+1])
			i++
			continue
		}
		switch c {
		case '|', '(', ')', '{', '}', '+', '?':
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func walkFiles(e *Env, root string) []string {
	var out []string
	var walk func(p, shown string)
	walk = func(p, shown string) {
		n, err := e.sh.fs.Stat(e.sh.user, p)
		if err != nil {
			return
		}
		if !n.IsDir() {
			out = append(out, shown)
			return
		}
		children, err := e.sh.fs.ReadDir(e.sh.user, p)
		if err != nil {
			fmt.Fprintf(e.Stderr, "grep: %s: %s\n", shown, err)
			return
		}
		for _, c := range children {
			if c.IsLink() {
				continue
			}
			walk(p+"/"+c.Name, strings.TrimSuffix(shown, "/")+"/"+c.Name)
		}
	}
	walk(e.sh.resolve(root), root)
	return out
}

func cmdSort(e *Env) int {
	o := getopt(e.Args[1:], "k", "t", "o")
	data, status := e.input(o.pos)
	lines := splitLines(data)
	key := func(l string) string { return l }
	if k, ok := o.val("k"); ok {
		idx, _ := strconv.Atoi(strings.SplitN(k, ",", 2)[0])
		sep, hasSep := o.val("t")
		key = func(l string) string {
			var f []string
			if hasSep {
				f = strings.Split(l, sep)
			} else {
				f = strings.Fields(l)
			}
			if idx >= 1 && idx <= len(f) {
				return f[idx-1]
			}
			return ""
		}
	}
	num := o.has("n", "h", "numeric-sort", "g")
	sort.SliceStable(lines, func(i, j int) bool {
		a, b := key(lines[i]), key(lines[j])
		if num {
			x, _ := strconv.ParseFloat(strings.TrimSpace(a), 64)
			y, _ := strconv.ParseFloat(strings.TrimSpace(b), 64)
			if x != y {
				return x < y
			}
		}
		return a < b
	})
	if o.has("r", "reverse") {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	if o.has("u", "unique") {
		var u []string
		for i, l := range lines {
			if i == 0 || l != lines[i-1] {
				u = append(u, l)
			}
		}
		lines = u
	}
	for _, l := range lines {
		e.Printf("%s\n", l)
	}
	return status
}

func cmdUniq(e *Env) int {
	o := getopt(e.Args[1:])
	data, status := e.input(o.pos)
	lines := splitLines(data)
	for i := 0; i < len(lines); {
		j := i
		for j < len(lines) && lines[j] == lines[i] {
			j++
		}
		n := j - i
		if (o.has("d") && n < 2) || (o.has("u") && n > 1) {
			i = j
			continue
		}
		if o.has("c", "count") {
			e.Printf("%7d %s\n", n, lines[i])
		} else {
			e.Printf("%s\n", lines[i])
		}
		i = j
	}
	return status
}

// parseRanges parses cut-style field lists like 1,3-5,7-.
func parseRanges(spec string) func(int) bool {
	type rng struct{ lo, hi int }
	var rs []rng
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		r := rng{1, 1 << 30}
		if lo != "" {
			r.lo, _ = strconv.Atoi(lo)
		}
		if !isRange {
			r.hi = r.lo
		} else if hi != "" {
			r.hi, _ = strconv.Atoi(hi)
		}
		rs = append(rs, r)
	}
	return func(i int) bool {
		for _, r := range rs {
			if i >= r.lo && i <= r.hi {
				return true
			}
		}
		return false
	}
}

func cmdCut(e *Env) int {
	o := getopt(e.Args[1:], "d", "f", "c", "b", "delimiter", "fields", "characters")
	data, status := e.input(o.pos)
	delim, ok := o.val("d", "delimiter")
	if !ok {
		delim = "\t"
	}
	if fspec, ok := o.val("f", "fields"); ok {
		in := parseRanges(fspec)
		for _, l := range splitLines(data) {
			if !strings.Contains(l, delim) {
				if !o.has("s") {
					e.Printf("%s\n", l)
				}
				continue
			}
			var sel []string
			for i, f := range strings.Split(l, delim) {
				if in(i + 1) {
					sel = append(sel, f)
				}
			}
			e.Printf("%s\n", strings.Join(sel, delim))
		}
		return status
	}
	if cspec, ok := o.val("c", "b", "characters"); ok {
		in := parseRanges(cspec)
		for _, l := range splitLines(data) {
			var b strings.Builder
			for i, r := range []rune(l) {
				if in(i + 1) {
					b.WriteRune(r)
				}
			}
			e.Printf("%s\n", b.String())
		}
		return status
	}
	fmt.Fprintln(e.Stderr, "cut: you must specify a list of bytes, characters, or fields\nTry 'cut --help' for more information.")
	return 1
}

// expandSet expands tr character sets such as a-z and [:upper:].
func expandSet(s string) []rune {
	classes := map[string]string{
		"[:upper:]": "A-Z", "[:lower:]": "a-z", "[:digit:]": "0-9",
		"[:alpha:]": "a-zA-Z", "[:alnum:]": "a-zA-Z0-9", "[:space:]": " \t\n\r\v\f",
	}
	for k, v := range classes {
		s = strings.ReplaceAll(s, k, v)
	}
	s, _ = unescape(s)
	rs := []rune(s)
	var out []rune
	for i := 0; i < len(rs); i++ {
		if i+2 < len(rs) && rs[i+1] == '-' && rs[i] <= rs[i+2] {
			for c := rs[i]; c <= rs[i+2]; c++ {
				out = append(out, c)
			}
			i += 2
			continue
		}
		out = append(out, rs[i])
	}
	return out
}

func cmdTr(e *Env) int {
	o := getopt(e.Args[1:])
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "tr: missing operand\nTry 'tr --help' for more information.")
		return 1
	}
	set1 := expandSet(o.pos[0])
	in := map[rune]bool{}
	for _, r := range set1 {
		in[r] = true
	}
	data := e.ReadStdin()
	var b strings.Builder
	if o.has("d", "delete") {
		for _, r := range data {
			if in[r] != o.has("c", "C") {
				continue
			}
			b.WriteRune(r)
		}
		e.Print(b.String())
		return 0
	}
	if o.has("s") && len(o.pos) == 1 {
		var last rune = -1
		for _, r := range data {
			if r == last && in[r] {
				continue
			}
			b.WriteRune(r)
			last = r
		}
		e.Print(b.String())
		return 0
	}
	if len(o.pos) < 2 {
		fmt.Fprintf(e.Stderr, "tr: missing operand after '%s'\n", o.pos[0])
		return 1
	}
	set2 := expandSet(o.pos[1])
	m := map[rune]rune{}
	for i, r := range set1 {
		if len(set2) == 0 {
			break
		}
		m[r] = set2[min(i, len(set2)-1)]
	}
	for _, r := range data {
		if t, ok := m[r]; ok {
			r = t
		}
		b.WriteRune(r)
	}
	e.Print(b.String())
	return 0
}

func cmdTee(e *Env) int {
	o := getopt(e.Args[1:])
	data := e.ReadStdin()
	e.Print(data)
	status := 0
	for _, f := range o.pos {
		if err := e.sh.fs.WriteFile(e.sh.user, e.sh.resolve(f), []byte(data), o.has("a", "append")); err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
		}
	}
	return status
}

// cmdAwk supports the overwhelmingly common one-liners: printing fields,
// optionally with a regex filter and -F separator, plus NR/NF and END{print NR}.
func cmdAwk(e *Env) int {
	o := getopt(e.Args[1:], "F", "v", "f")
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "usage: awk [POSIX or GNU style options] -f progfile [--] file ...\nusage: awk [POSIX or GNU style options] [--] 'program' file ...")
		return 2
	}
	prog := strings.TrimSpace(o.pos[0])
	data, status := e.input(o.pos[1:])
	sep, hasSep := o.val("F")
	if sep == `\t` {
		sep = "\t"
	}

	var filter *regexp.Regexp
	if strings.HasPrefix(prog, "/") {
		if end := strings.Index(prog[1:], "/"); end >= 0 {
			filter, _ = regexp.Compile(prog[1 : end+1])
			prog = strings.TrimSpace(prog[end+2:])
		}
	}
	endProg := ""
	if i := strings.Index(prog, "END"); i >= 0 {
		endProg = strings.TrimSpace(prog[i+3:])
		prog = strings.TrimSpace(prog[:i])
	}
	body := strings.TrimSuffix(strings.TrimPrefix(prog, "{"), "}")
	if prog == "" && endProg == "" {
		body = "print"
	}

	nr := 0
	var sum float64
	eval := func(stmt string, fields []string, line string) string {
		stmt = strings.TrimSpace(stmt)
		if name, expr, ok := strings.Cut(stmt, "+="); ok && (name == "sum" || name == "s") {
			if strings.HasPrefix(expr, "$") {
				idx, _ := strconv.Atoi(expr[1:])
				if idx >= 1 && idx <= len(fields) {
					v, _ := strconv.ParseFloat(fields[idx-1], 64)
					sum += v
				}
			}
			return ""
		}
		if !strings.HasPrefix(stmt, "print") {
			return ""
		}
		args := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(stmt, "printf"), "print"))
		if args == "" {
			return line + "\n"
		}
		var parts []string
		for _, a := range splitAwkArgs(args) {
			a = strings.TrimSpace(a)
			switch {
			case a == "$0":
				parts = append(parts, line)
			case a == "NR":
				parts = append(parts, strconv.Itoa(nr))
			case a == "NF":
				parts = append(parts, strconv.Itoa(len(fields)))
			case a == "$NF":
				if len(fields) > 0 {
					parts = append(parts, fields[len(fields)-1])
				} else {
					parts = append(parts, "")
				}
			case a == "sum" || a == "s":
				parts = append(parts, strconv.FormatFloat(sum, 'f', -1, 64))
			case strings.HasPrefix(a, "$"):
				idx, _ := strconv.Atoi(a[1:])
				if idx >= 1 && idx <= len(fields) {
					parts = append(parts, fields[idx-1])
				} else {
					parts = append(parts, "")
				}
			case strings.HasPrefix(a, `"`):
				s, _ := unescape(strings.Trim(a, `"`))
				parts = append(parts, s)
			default:
				parts = append(parts, a)
			}
		}
		if strings.HasPrefix(stmt, "printf") {
			out, _ := sprintf(parts[0], parts[1:])
			return out
		}
		return strings.Join(parts, " ") + "\n"
	}

	var out strings.Builder
	for _, line := range splitLines(data) {
		nr++
		if filter != nil && !filter.MatchString(line) {
			continue
		}
		var fields []string
		if hasSep {
			fields = strings.Split(line, sep)
		} else {
			fields = strings.Fields(line)
		}
		if body == "" {
			continue
		}
		for _, stmt := range strings.Split(body, ";") {
			out.WriteString(eval(stmt, fields, line))
		}
	}
	if endProg != "" {
		body := strings.TrimSuffix(strings.TrimPrefix(endProg, "{"), "}")
		for _, stmt := range strings.Split(body, ";") {
			out.WriteString(eval(stmt, nil, ""))
		}
	}
	e.Print(out.String())
	return status
}

// splitAwkArgs splits print arguments on commas and spaces outside quotes.
func splitAwkArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case !inQ && (c == ',' || c == ' '):
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// cmdSed supports s/// substitutions (with g and i flags), line deletion and
// printing by number or regex, -n and -i.
func cmdSed(e *Env) int {
	o := getopt(e.Args[1:], "e", "expression")
	var scripts []string
	if v, ok := o.val("e", "expression"); ok {
		scripts = append(scripts, v)
	}
	files := o.pos
	if len(scripts) == 0 {
		if len(files) == 0 {
			fmt.Fprintln(e.Stderr, "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...")
			return 1
		}
		scripts = append(scripts, files[0])
		files = files[1:]
	}
	quiet := o.has("n", "quiet", "silent")
	apply := func(text string) (string, error) {
		lines := splitLines(text)
		var out strings.Builder
		for _, script := range scripts {
			for _, cmd := range strings.Split(script, ";") {
				cmd = strings.TrimSpace(cmd)
				if cmd == "" {
					continue
				}
				var err error
				lines, err = sedApply(cmd, lines, quiet, &out)
				if err != nil {
					return "", err
				}
			}
		}
		if !quiet {
			for _, l := range lines {
				out.WriteString(l + "\n")
			}
		}
		return out.String(), nil
	}
	if o.has("i", "in-place") {
		status := 0
		for _, f := range files {
			p := e.sh.resolve(f)
			data, err := e.sh.fs.ReadFile(e.sh.user, p)
			if err != nil {
				e.Errorf("can't read %s: %s", f, err)
				status = 2
				continue
			}
			res, err := apply(string(data))
			if err != nil {
				e.Errorf("-e expression #1, char 1: %s", err)
				return 1
			}
			if err := e.sh.fs.WriteFile(e.sh.user, p, []byte(res), false); err != nil {
				e.Errorf("couldn't open temporary file %s: %s", f, err)
				status = 4
			}
		}
		return status
	}
	data, status := e.input(files)
	res, err := apply(data)
	if err != nil {
		e.Errorf("-e expression #1, char 1: %s", err)
		return 1
	}
	e.Print(res)
	return status
}

func sedApply(cmd string, lines []string, quiet bool, printed *strings.Builder) ([]string, error) {
	// Optional address: N, $, or /re/.
	match := func(int, string) bool { return true }
	switch {
	case strings.HasPrefix(cmd, "/"):
		end := strings.Index(cmd[1:], "/")
		if end < 0 {
			return nil, fmt.Errorf("unterminated address regex")
		}
		re, err := regexp.Compile(basicToExtended(cmd[1 : end+1]))
		if err != nil {
			return nil, fmt.Errorf("invalid regex")
		}
		match = func(_ int, l string) bool { return re.MatchString(l) }
		cmd = cmd[end+2:]
	case len(cmd) > 0 && cmd[0] >= '0' && cmd[0] <= '9':
		j := 0
		for j < len(cmd) && cmd[j] >= '0' && cmd[j] <= '9' {
			j++
		}
		n, _ := strconv.Atoi(cmd[:j])
		match = func(i int, _ string) bool { return i+1 == n }
		cmd = cmd[j:]
	case strings.HasPrefix(cmd, "$"):
		match = func(i int, _ string) bool { return i == len(lines)-1 }
		cmd = cmd[1:]
	}
	if cmd == "" {
		return nil, fmt.Errorf("missing command")
	}
	switch cmd[0] {
	case 'd':
		var out []string
		for i, l := range lines {
			if !match(i, l) {
				out = append(out, l)
			}
		}
		return out, nil
	case 'p':
		var out []string
		for i, l := range lines {
			if match(i, l) {
				if quiet {
					printed.WriteString(l + "\n")
				} else {
					out = append(out, l)
				}
			}
			out = append(out, l)
		}
		if quiet {
			return lines, nil
		}
		return out, nil
	case 's':
		if len(cmd) < 2 {
			return nil, fmt.Errorf("unterminated `s' command")
		}
		delim := string(cmd[1])
		parts := strings.Split(cmd[2:], delim)
		if len(parts) < 3 {
			return nil, fmt.Errorf("unterminated `s' command")
		}
		pat, repl, flags := parts[0], parts[1], parts[2]
		if strings.Contains(flags, "I") || strings.Contains(flags, "i") {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(basicToExtended(pat))
		if err != nil {
			return nil, fmt.Errorf("invalid regex")
		}
		repl = strings.ReplaceAll(repl, "&", "${0}")
		for d := 1; d <= 9; d++ {
			repl = strings.ReplaceAll(repl, fmt.Sprintf("\\%d", d), fmt.Sprintf("${%d}", d))
		}
		out := make([]string, len(lines))
		for i, l := range lines {
			if !match(i, l) {
				out[i] = l
				continue
			}
			if strings.Contains(flags, "g") {
				out[i] = re.ReplaceAllString(l, repl)
			} else if loc := re.FindStringSubmatchIndex(l); loc != nil {
				var dst []byte
				dst = re.ExpandString(dst, repl, l, loc)
				out[i] = l[:loc[0]] + string(dst) + l[loc[1]:]
			} else {
				out[i] = l
			}
			if strings.Contains(flags, "p") && quiet {
				printed.WriteString(out[i] + "\n")
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown command: `%c'", cmd[0])
}

func cmdXargs(e *Env) int {
	o := getopt(e.Args[1:], "n", "I", "d", "P", "L")
	args := e.Args[1:]
	// Find where the command begins: the first positional in o.pos.
	cmd := []string{"echo"}
	if len(o.pos) > 0 {
		for i, a := range args {
			if a == o.pos[0] {
				cmd = args[i:]
				break
			}
		}
	}
	items := strings.Fields(e.ReadStdin())
	if repl, ok := o.val("I"); ok {
		status := 0
		for _, item := range items {
			var argv []string
			for _, a := range cmd {
				argv = append(argv, strings.ReplaceAll(a, repl, item))
			}
			status = e.sh.run(e.Ctx, argv, strings.NewReader(""), e.Stdout, e.Stderr)
		}
		return status
	}
	if len(items) == 0 && o.has("r", "no-run-if-empty") {
		return 0
	}
	return e.sh.run(e.Ctx, append(append([]string{}, cmd...), items...), strings.NewReader(""), e.Stdout, e.Stderr)
}

func cmdBase64(e *Env) int {
	o := getopt(e.Args[1:], "w")
	data, status := e.input(o.pos)
	if o.has("d", "decode") {
		clean := strings.Join(strings.Fields(data), "")
		dec, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			dec, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "="))
		}
		e.Print(string(dec))
		if err != nil {
			fmt.Fprintln(e.Stderr, "base64: invalid input")
			return 1
		}
		return status
	}
	enc := base64.StdEncoding.EncodeToString([]byte(data))
	for len(enc) > 76 {
		e.Printf("%s\n", enc[:76])
		enc = enc[76:]
	}
	e.Printf("%s\n", enc)
	return status
}

func cmdHashsum(e *Env) int {
	var h func() hash.Hash
	switch e.Args[0] {
	case "md5sum":
		h = md5.New
	case "sha1sum":
		h = sha1.New
	default:
		h = sha256.New
	}
	o := getopt(e.Args[1:])
	if len(o.pos) == 0 {
		sum := h()
		sum.Write([]byte(e.ReadStdin()))
		e.Printf("%x  -\n", sum.Sum(nil))
		return 0
	}
	status := 0
	for _, f := range o.pos {
		data, err := e.sh.fs.ReadFile(e.sh.user, e.sh.resolve(f))
		if err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
			continue
		}
		sum := h()
		sum.Write(data)
		e.Printf("%x  %s\n", sum.Sum(nil), f)
	}
	return status
}

func cmdSeq(e *Env) int {
	o := getopt(e.Args[1:], "s")
	nums := make([]int, 0, 3)
	for _, a := range o.pos {
		n, err := strconv.Atoi(a)
		if err != nil {
			e.Errorf("invalid floating point argument: '%s'", a)
			return 1
		}
		nums = append(nums, n)
	}
	first, step, last := 1, 1, 0
	switch len(nums) {
	case 1:
		last = nums[0]
	case 2:
		first, last = nums[0], nums[1]
	case 3:
		first, step, last = nums[0], nums[1], nums[2]
	default:
		fmt.Fprintln(e.Stderr, "seq: missing operand")
		return 1
	}
	sep, ok := o.val("s")
	if !ok {
		sep = "\n"
	}
	var out []string
	for i := first; (step > 0 && i <= last) || (step < 0 && i >= last); i += step {
		out = append(out, strconv.Itoa(i))
		if len(out) > 100000 || step == 0 {
			break
		}
	}
	if len(out) > 0 {
		e.Printf("%s\n", strings.Join(out, sep))
	}
	return 0
}

func cmdYes(e *Env) int {
	word := "y"
	if len(e.Args) > 1 {
		word = strings.Join(e.Args[1:], " ")
	}
	// Bounded so `yes` without a pipe cannot spin forever.
	line := word + "\n"
	for i := 0; i < 2000; i++ {
		if e.Ctx.Err() != nil {
			return 130
		}
		e.Print(line)
	}
	if e.isTTY() {
		for e.Sleep(50 * 1e6) {
			e.Print(strings.Repeat(line, 50))
		}
		return 130
	}
	return 0
}

func cmdRev(e *Env) int {
	data, status := e.input(e.Args[1:])
	for _, l := range splitLines(data) {
		r := []rune(l)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		e.Printf("%s\n", string(r))
	}
	return status
}

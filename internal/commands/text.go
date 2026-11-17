package commands

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "head", Run: cmdHead},
		shell.Command{Name: "tail", Run: cmdTail},
		shell.Command{Name: "wc", Run: cmdWc},
		shell.Command{Name: "sort", Run: cmdSort},
		shell.Command{Name: "uniq", Run: cmdUniq},
		shell.Command{Name: "cut", Run: cmdCut},
		shell.Command{Name: "tr", Run: cmdTr},
		shell.Command{Name: "tee", Run: cmdTee},
		shell.Command{Name: "base64", Run: cmdBase64},
		shell.Command{Name: "md5sum", Aliases: []string{"sha1sum", "sha256sum"}, Run: cmdHashsum},
		shell.Command{Name: "seq", Run: cmdSeq},
		shell.Command{Name: "yes", Run: cmdYes},
		shell.Command{Name: "rev", Run: cmdRev},
	)
}

func cmdHead(e *shell.Env) int {
	n, _, files := countArg(e.Args[1:])
	data, status := e.ReadFiles(files)
	lines := splitLines(data)
	switch {
	case n < 0: // head -n -N: all but the last N lines
		lines = lines[:max(0, len(lines)+n)]
	case n < len(lines):
		lines = lines[:n]
	}
	for _, l := range lines {
		e.Printf("%s\n", l)
	}
	return status
}

func cmdTail(e *shell.Env) int {
	n, from, files := countArg(e.Args[1:])
	n = max(n, -n) // tail -n -N is the same as tail -n N
	data, status := e.ReadFiles(files)
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

func cmdWc(e *shell.Env) int {
	o := e.Flags()
	count := func(s string) (int, int, int) {
		return strings.Count(s, "\n"), len(strings.Fields(s)), len(s)
	}
	show := func(l, w, c int, name string) {
		var parts []string
		all := !o.Has("l", "w", "c", "m", "lines", "words", "bytes", "chars")
		if all || o.Has("l", "lines") {
			parts = append(parts, strconv.Itoa(l))
		}
		if all || o.Has("w", "words") {
			parts = append(parts, strconv.Itoa(w))
		}
		if all || o.Has("c", "m", "bytes", "chars") {
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
	if len(o.Args) == 0 {
		l, w, c := count(e.ReadStdin())
		show(l, w, c, "")
		return 0
	}
	status := 0
	var tl, tw, tc int
	for _, f := range o.Args {
		data, err := e.FS.ReadFile(f)
		if err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
			continue
		}
		l, w, c := count(string(data))
		tl, tw, tc = tl+l, tw+w, tc+c
		show(l, w, c, f)
	}
	if len(o.Args) > 1 {
		show(tl, tw, tc, "total")
	}
	return status
}

func cmdSort(e *shell.Env) int {
	o := e.Flags("k", "t", "o")
	data, status := e.ReadFiles(o.Args)
	lines := splitLines(data)
	key := func(l string) string { return l }
	if k, ok := o.Value("k"); ok {
		idx, _ := strconv.Atoi(strings.SplitN(k, ",", 2)[0])
		sep, hasSep := o.Value("t")
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
	num := o.Has("n", "h", "numeric-sort", "g")
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
	if o.Has("r", "reverse") {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	if o.Has("u", "unique") {
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

func cmdUniq(e *shell.Env) int {
	o := e.Flags()
	data, status := e.ReadFiles(o.Args)
	lines := splitLines(data)
	for i := 0; i < len(lines); {
		j := i
		for j < len(lines) && lines[j] == lines[i] {
			j++
		}
		n := j - i
		if (o.Has("d") && n < 2) || (o.Has("u") && n > 1) {
			i = j
			continue
		}
		if o.Has("c", "count") {
			e.Printf("%7d %s\n", n, lines[i])
		} else {
			e.Printf("%s\n", lines[i])
		}
		i = j
	}
	return status
}

func cmdCut(e *shell.Env) int {
	o := e.Flags("d", "f", "c", "b", "delimiter", "fields", "characters")
	data, status := e.ReadFiles(o.Args)
	delim, ok := o.Value("d", "delimiter")
	if !ok {
		delim = "\t"
	}
	if fspec, ok := o.Value("f", "fields"); ok {
		in := parseRanges(fspec)
		for _, l := range splitLines(data) {
			if !strings.Contains(l, delim) {
				if !o.Has("s") {
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
	if cspec, ok := o.Value("c", "b", "characters"); ok {
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

func cmdTr(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "tr: missing operand\nTry 'tr --help' for more information.")
		return 1
	}
	set1 := expandSet(o.Args[0])
	in := map[rune]bool{}
	for _, r := range set1 {
		in[r] = true
	}
	data := e.ReadStdin()
	var b strings.Builder
	if o.Has("d", "delete") {
		for _, r := range data {
			if in[r] != o.Has("c", "C") {
				continue
			}
			b.WriteRune(r)
		}
		e.Print(b.String())
		return 0
	}
	if o.Has("s") && len(o.Args) == 1 {
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
	if len(o.Args) < 2 {
		fmt.Fprintf(e.Stderr, "tr: missing operand after '%s'\n", o.Args[0])
		return 1
	}
	set2 := expandSet(o.Args[1])
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

// expandSet expands tr character sets such as a-z and [:upper:].
func expandSet(s string) []rune {
	classes := map[string]string{
		"[:upper:]": "A-Z", "[:lower:]": "a-z", "[:digit:]": "0-9",
		"[:alpha:]": "a-zA-Z", "[:alnum:]": "a-zA-Z0-9", "[:space:]": " \t\n\r\v\f",
	}
	for k, v := range classes {
		s = strings.ReplaceAll(s, k, v)
	}
	s, _ = shell.Unescape(s)
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

func cmdTee(e *shell.Env) int {
	o := e.Flags()
	data := e.ReadStdin()
	e.Print(data)
	status := 0
	for _, f := range o.Args {
		write := e.FS.WriteFile
		if o.Has("a", "append") {
			write = e.FS.AppendFile
		}
		if err := write(f, []byte(data)); err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
		}
	}
	return status
}

func cmdBase64(e *shell.Env) int {
	o := e.Flags("w")
	data, status := e.ReadFiles(o.Args)
	if o.Has("d", "decode") {
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

func cmdHashsum(e *shell.Env) int {
	var h func() hash.Hash
	switch e.Args[0] {
	case "md5sum":
		h = md5.New
	case "sha1sum":
		h = sha1.New
	default:
		h = sha256.New
	}
	o := e.Flags()
	if len(o.Args) == 0 {
		sum := h()
		sum.Write([]byte(e.ReadStdin()))
		e.Printf("%x  -\n", sum.Sum(nil))
		return 0
	}
	status := 0
	for _, f := range o.Args {
		data, err := e.FS.ReadFile(f)
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

func cmdSeq(e *shell.Env) int {
	o := e.Flags("s")
	nums := make([]int, 0, 3)
	for _, a := range o.Args {
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
	sep, ok := o.Value("s")
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

func cmdYes(e *shell.Env) int {
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
	if e.IsTTY() {
		for e.Sleep(50 * 1e6) {
			e.Print(strings.Repeat(line, 50))
		}
		return 130
	}
	return 0
}

func cmdRev(e *shell.Env) int {
	data, status := e.ReadFiles(e.Args[1:])
	for _, l := range splitLines(data) {
		r := []rune(l)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		e.Printf("%s\n", string(r))
	}
	return status
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

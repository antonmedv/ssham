package shell

import (
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/vfs"
)

func builtinCd(e *Env) int {
	s := e.sh
	target := s.user.Home
	if len(e.Args) > 1 {
		target = e.Args[1]
	}
	if target == "-" {
		target = s.getVar("OLDPWD")
		if target == "" {
			target = s.cwd
		}
		e.Printf("%s\n", target)
	}
	p := s.resolve(target)
	n, err := s.fs.Stat(s.user.Name, p)
	switch {
	case err != nil:
		sh(e, "cd: can't cd to %s: %s", target, err)
		return 2
	case !n.IsDir():
		sh(e, "cd: can't cd to %s: Not a directory", target)
		return 2
	case !vfs.CanAccess(n, s.user.Name, vfs.Exec):
		sh(e, "cd: can't cd to %s: Permission denied", target)
		return 2
	}
	s.vars["OLDPWD"] = s.cwd
	s.cwd = p
	s.vars["PWD"] = p
	return 0
}

func builtinPwd(e *Env) int {
	e.Printf("%s\n", e.sh.cwd)
	return 0
}

func builtinEcho(e *Env) int {
	args := e.Args[1:]
	newline, escapes := true, false
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' && strings.Trim(args[0][1:], "neE") == "" {
		for _, c := range args[0][1:] {
			switch c {
			case 'n':
				newline = false
			case 'e':
				escapes = true
			case 'E':
				escapes = false
			}
		}
		args = args[1:]
	}
	out := strings.Join(args, " ")
	if escapes {
		var stop bool
		out, stop = Unescape(out)
		if stop {
			newline = false
		}
	}
	if newline {
		out += "\n"
	}
	e.Print(out)
	return 0
}

// unescape interprets backslash escapes as echo -e and printf do. stop is
// true if \c was seen.
func Unescape(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e':
			b.WriteByte(0x1b)
		case '\\':
			b.WriteByte('\\')
		case 'c':
			return b.String(), true
		case 'x':
			j := i + 1
			for j < len(s) && j < i+3 && strings.IndexByte("0123456789abcdefABCDEF", s[j]) >= 0 {
				j++
			}
			if v, err := strconv.ParseUint(s[i+1:j], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i = j - 1
			} else {
				b.WriteString("\\x")
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			// Octal: \0NNN (echo -e, %b) or \NNN (printf formats).
			start := i
			if s[i] == '0' {
				start++
			}
			j := start
			for j < len(s) && j < start+3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint("0"+s[start:j], 8, 8)
			b.WriteByte(byte(v))
			i = j - 1
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String(), false
}

func builtinPrintf(e *Env) int {
	if len(e.Args) < 2 {
		fmt.Fprintln(e.Stderr, "printf: usage: printf [-v var] format [arguments]")
		return 2
	}
	format, args := e.Args[1], e.Args[2:]
	for {
		out, used := Sprintf(format, args)
		e.Print(out)
		if used == 0 || used >= len(args) {
			break
		}
		args = args[used:]
	}
	return 0
}

// sprintf implements the subset of printf(1) formats used in practice.
func Sprintf(format string, args []string) (string, int) {
	var b strings.Builder
	used := 0
	next := func() string {
		if used < len(args) {
			used++
			return args[used-1]
		}
		return ""
	}
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '%' || i+1 >= len(format) {
			// Literal text up to the next directive, with escapes.
			j := i + 1
			for j < len(format) && format[j] != '%' {
				j++
			}
			text, _ := Unescape(format[i:j])
			b.WriteString(text)
			i = j - 1
			continue
		}
		j := i + 1
		for j < len(format) && strings.IndexByte("-+ #0123456789.", format[j]) >= 0 {
			j++
		}
		if j >= len(format) {
			b.WriteString(format[i:])
			break
		}
		spec := format[i+1 : j]
		switch verb := format[j]; verb {
		case '%':
			b.WriteByte('%')
		case 's':
			fmt.Fprintf(&b, "%"+spec+"s", next())
		case 'b':
			s, _ := Unescape(next())
			fmt.Fprintf(&b, "%"+spec+"s", s)
		case 'd', 'i':
			n, _ := strconv.ParseInt(next(), 0, 64)
			fmt.Fprintf(&b, "%"+spec+"d", n)
		case 'u':
			n, _ := strconv.ParseUint(next(), 0, 64)
			fmt.Fprintf(&b, "%"+spec+"d", n)
		case 'x', 'X', 'o':
			n, _ := strconv.ParseInt(next(), 0, 64)
			fmt.Fprintf(&b, "%"+spec+string(verb), n)
		case 'f', 'e', 'g':
			n, _ := strconv.ParseFloat(next(), 64)
			fmt.Fprintf(&b, "%"+spec+string(verb), n)
		case 'c':
			if s := next(); s != "" {
				b.WriteByte(s[0])
			}
		default:
			b.WriteString(format[i : j+1])
		}
		i = j
	}
	return b.String(), used
}

// builtinTest implements the common forms of test / [.
func builtinTest(e *Env) int {
	args := e.Args[1:]
	switch e.Args[0] {
	case "[":
		if len(args) == 0 || args[len(args)-1] != "]" {
			sh(e, "missing ]")
			return 2
		}
		args = args[:len(args)-1]
	case "[[":
		if len(args) == 0 || args[len(args)-1] != "]]" {
			sh(e, "missing ]]")
			return 2
		}
		args = args[:len(args)-1]
	}
	t := &tester{sh: e.sh, args: args, bash: e.Args[0] == "[["}
	if len(args) == 0 {
		return 1
	}
	r := t.or()
	if t.err == "" && t.pos < len(args) {
		t.err = args[t.pos] + ": unexpected operator"
	}
	if t.err != "" {
		sh(e, "%s", t.err)
		return 2
	}
	if r {
		return 0
	}
	return 1
}

// tester evaluates test expressions: ! -a -o ( ), and the unary and
// binary primaries. In [[ ]], == and != match patterns and && || work.
type tester struct {
	sh   *Shell
	args []string
	pos  int
	bash bool
	err  string
}

func (t *tester) peek(n int) (string, bool) {
	if t.pos+n < len(t.args) {
		return t.args[t.pos+n], true
	}
	return "", false
}

func (t *tester) or() bool {
	r := t.and()
	for {
		op, _ := t.peek(0)
		if op != "-o" && !(t.bash && op == "||") {
			return r
		}
		t.pos++
		r = t.and() || r
	}
}

func (t *tester) and() bool {
	r := t.not()
	for {
		op, _ := t.peek(0)
		if op != "-a" && !(t.bash && op == "&&") {
			return r
		}
		t.pos++
		r = t.not() && r
	}
}

func (t *tester) not() bool {
	if a, ok := t.peek(0); ok && a == "!" {
		if _, more := t.peek(1); more {
			t.pos++
			return !t.not()
		}
	}
	return t.primary()
}

var testBinary = map[string]bool{
	"=": true, "==": true, "!=": true, "<": true, ">": true,
	"-eq": true, "-ne": true, "-lt": true, "-le": true, "-gt": true, "-ge": true,
	"-nt": true, "-ot": true, "-ef": true, "=~": true,
}

func (t *tester) primary() bool {
	a, ok := t.peek(0)
	if !ok {
		t.err = "argument expected"
		return false
	}
	if op, ok := t.peek(1); ok && testBinary[op] {
		r, _ := t.peek(2)
		t.pos += 3
		return t.binary(a, op, r)
	}
	if a == "(" {
		t.pos++
		r := t.or()
		if c, _ := t.peek(0); c != ")" {
			t.err = "missing )"
			return false
		}
		t.pos++
		return r
	}
	if len(a) == 2 && a[0] == '-' && strings.Contains("zneafdLhsrwxcbpSgukGOt", a[1:]) {
		if arg, ok := t.peek(1); ok {
			t.pos += 2
			return t.unary(a, arg)
		}
	}
	t.pos++
	return a != ""
}

func (t *tester) unary(op, a string) bool {
	s := t.sh
	switch op {
	case "-z":
		return a == ""
	case "-n":
		return a != ""
	case "-t":
		return a == "0" && s.cfg.Term != ""
	}
	p := s.resolve(a)
	if op == "-L" || op == "-h" {
		n, err := s.fs.Lstat(s.user.Name, p)
		return err == nil && n.IsLink()
	}
	n, err := s.fs.Stat(s.user.Name, p)
	if err != nil {
		return false
	}
	switch op {
	case "-e", "-a":
		return true
	case "-f":
		return !n.IsDir() && !n.IsDevice()
	case "-d":
		return n.IsDir()
	case "-c":
		return n.IsDevice() && n.Mode&fs.ModeCharDevice != 0
	case "-b":
		return n.IsDevice() && n.Mode&fs.ModeCharDevice == 0
	case "-s":
		return n.Size() > 0
	case "-u":
		return n.Mode&fs.ModeSetuid != 0 || n.Mode&0o4000 != 0
	case "-g":
		return n.Mode&fs.ModeSetgid != 0 || n.Mode&0o2000 != 0
	case "-k":
		return n.Mode&fs.ModeSticky != 0 || n.Mode&0o1000 != 0
	case "-O", "-G":
		return n.Owner == s.user.Name
	case "-r", "-w", "-x":
		want := map[string]fs.FileMode{"-r": vfs.Read, "-w": vfs.Write, "-x": vfs.Exec}[op]
		if op == "-w" && s.fs.IsReadOnly(p) {
			return false
		}
		return vfs.CanAccess(n, s.user.Name, want)
	}
	return false
}

func (t *tester) binary(l, op, r string) bool {
	switch op {
	case "=", "==", "!=":
		eq := l == r
		if t.bash {
			re := patternRegexp(r)
			eq = re != nil && re.MatchString(l)
		}
		return eq == (op != "!=")
	case "<":
		return l < r
	case ">":
		return l > r
	case "=~":
		re, err := regexp.Compile(r)
		return err == nil && re.MatchString(l)
	case "-nt", "-ot", "-ef":
		a, err1 := t.sh.fs.Stat(t.sh.user.Name, t.sh.resolve(l))
		b, err2 := t.sh.fs.Stat(t.sh.user.Name, t.sh.resolve(r))
		if err1 != nil || err2 != nil {
			return false
		}
		switch op {
		case "-nt":
			return a.ModTime.After(b.ModTime)
		case "-ot":
			return a.ModTime.Before(b.ModTime)
		}
		return a == b
	}
	li, err1 := strconv.ParseInt(strings.TrimSpace(l), 10, 64)
	ri, err2 := strconv.ParseInt(strings.TrimSpace(r), 10, 64)
	if err1 != nil || err2 != nil {
		bad := l
		if err1 == nil {
			bad = r
		}
		t.err = bad + ": bad number"
		return false
	}
	switch op {
	case "-eq":
		return li == ri
	case "-ne":
		return li != ri
	case "-lt":
		return li < ri
	case "-le":
		return li <= ri
	case "-gt":
		return li > ri
	}
	return li >= ri
}

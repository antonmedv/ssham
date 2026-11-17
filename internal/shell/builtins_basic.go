package shell

import (
	"fmt"
	"io/fs"
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
	if len(e.Args) > 2 {
		fmt.Fprintln(e.Stderr, "-bash: cd: too many arguments")
		return 1
	}
	if target == "-" {
		target = s.getVar("OLDPWD")
		if target == "" {
			fmt.Fprintln(e.Stderr, "-bash: cd: OLDPWD not set")
			return 1
		}
		e.Printf("%s\n", target)
	}
	p := s.resolve(target)
	n, err := s.fs.Stat(s.user.Name, p)
	if err != nil {
		fmt.Fprintf(e.Stderr, "-bash: cd: %s: %s\n", target, err)
		return 1
	}
	if !n.IsDir() {
		fmt.Fprintf(e.Stderr, "-bash: cd: %s: Not a directory\n", target)
		return 1
	}
	if !vfs.CanAccess(n, s.user.Name, 1) {
		fmt.Fprintf(e.Stderr, "-bash: cd: %s: Permission denied\n", target)
		return 1
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
	if e.Args[0] == "[" {
		if len(args) == 0 || args[len(args)-1] != "]" {
			fmt.Fprintln(e.Stderr, "-bash: [: missing `]'")
			return 2
		}
		args = args[:len(args)-1]
	}
	neg := false
	for len(args) > 0 && args[0] == "!" {
		neg = !neg
		args = args[1:]
	}
	r := evalTest(e.sh, args)
	if neg {
		r = !r
	}
	if r {
		return 0
	}
	return 1
}

func evalTest(s *Shell, a []string) bool {
	switch len(a) {
	case 0:
		return false
	case 1:
		return a[0] != ""
	case 2:
		p := s.resolve(a[1])
		switch a[0] {
		case "-z":
			return a[1] == ""
		case "-n":
			return a[1] != ""
		case "-e", "-a":
			_, err := s.fs.Stat(s.user.Name, p)
			return err == nil
		case "-f":
			n, err := s.fs.Stat(s.user.Name, p)
			return err == nil && !n.IsDir()
		case "-d":
			n, err := s.fs.Stat(s.user.Name, p)
			return err == nil && n.IsDir()
		case "-L", "-h":
			n, err := s.fs.Lstat(s.user.Name, p)
			return err == nil && n.IsLink()
		case "-s":
			n, err := s.fs.Stat(s.user.Name, p)
			return err == nil && n.Size() > 0
		case "-r", "-w", "-x":
			n, err := s.fs.Stat(s.user.Name, p)
			want := map[string]fs.FileMode{"-r": vfs.Read, "-w": vfs.Write, "-x": vfs.Exec}[a[0]]
			return err == nil && vfs.CanAccess(n, s.user.Name, want)
		}
	case 3:
		l, r := a[0], a[2]
		switch a[1] {
		case "=", "==":
			return l == r
		case "!=":
			return l != r
		}
		li, err1 := strconv.Atoi(l)
		ri, err2 := strconv.Atoi(r)
		if err1 != nil || err2 != nil {
			return false
		}
		switch a[1] {
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
		case "-ge":
			return li >= ri
		}
	}
	return false
}

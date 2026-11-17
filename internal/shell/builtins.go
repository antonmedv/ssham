package shell

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

// Env is what a simulated command receives.
type Env struct {
	Ctx    context.Context
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	sh     *Shell
}

// Printf writes to stdout.
func (e *Env) Printf(format string, a ...any) { fmt.Fprintf(e.Stdout, format, a...) }

// Print writes s to stdout.
func (e *Env) Print(s string) { _, _ = io.WriteString(e.Stdout, s) }

// Errorf writes "name: message" to stderr.
func (e *Env) Errorf(format string, a ...any) {
	fmt.Fprintf(e.Stderr, e.Args[0]+": "+format+"\n", a...)
}

// ReadStdin reads all of stdin, up to the capture limit.
func (e *Env) ReadStdin() string {
	b, _ := io.ReadAll(io.LimitReader(e.Stdin, maxCaptureBytes))
	return string(b)
}

// Sleep waits for d or until the command is interrupted. It returns false
// if interrupted.
func (e *Env) Sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-e.Ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// opts holds parsed command-line flags.
type opts struct {
	flags map[string]bool   // short ("l") and long ("all") boolean flags
	vals  map[string]string // flags that take a value
	pos   []string
}

func (o opts) has(names ...string) bool {
	for _, n := range names {
		if o.flags[n] {
			return true
		}
	}
	return false
}

func (o opts) val(names ...string) (string, bool) {
	for _, n := range names {
		if v, ok := o.vals[n]; ok {
			return v, true
		}
	}
	return "", false
}

// getopt parses args (without argv[0]). valued lists flags (short letters
// or long names) that consume a value.
func getopt(args []string, valued ...string) opts {
	o := opts{flags: map[string]bool{}, vals: map[string]string{}}
	takes := map[string]bool{}
	for _, v := range valued {
		takes[v] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			o.pos = append(o.pos, args[i+1:]...)
			return o
		case strings.HasPrefix(a, "--") && len(a) > 2:
			name, val, hasVal := strings.Cut(a[2:], "=")
			if takes[name] {
				if !hasVal && i+1 < len(args) {
					i++
					val = args[i]
				}
				o.vals[name] = val
			} else {
				o.flags[name] = true
				if hasVal {
					o.vals[name] = val
				}
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				f := string(a[j])
				if takes[f] {
					val := a[j+1:]
					if val == "" && i+1 < len(args) {
						i++
						val = args[i]
					}
					o.vals[f] = val
					break
				}
				o.flags[f] = true
			}
		default:
			o.pos = append(o.pos, a)
		}
	}
	return o
}

var builtins map[string]func(*Env) int

func init() {
	builtins = map[string]func(*Env) int{
		"cd":      builtinCd,
		"pwd":     builtinPwd,
		"echo":    builtinEcho,
		"printf":  builtinPrintf,
		"export":  builtinExport,
		"unset":   builtinUnset,
		"alias":   builtinAlias,
		"unalias": builtinUnalias,
		"history": builtinHistory,
		"exit":    builtinExit,
		"logout":  builtinExit,
		"source":  builtinSource,
		".":       builtinSource,
		"type":    builtinType,
		"set":     builtinSet,
		"true":    func(*Env) int { return 0 },
		":":       func(*Env) int { return 0 },
		"false":   func(*Env) int { return 1 },
		"test":    builtinTest,
		"[":       builtinTest,
		"read":    builtinRead,
		"eval":    builtinEval,
		"exec":    builtinExec,
		"command": builtinCommand,
		"builtin": builtinCommand,
		"kill":    builtinKill,
		"jobs":    func(*Env) int { return 0 },
		"wait":    func(*Env) int { return 0 },
		"ulimit":  builtinUlimit,
		"umask":   func(e *Env) int { e.Print("0002\n"); return 0 },
		"shopt":   func(*Env) int { return 0 },
		"hash":    func(*Env) int { return 0 },
		"trap":    func(*Env) int { return 0 },
		"help":    builtinHelp,
		"enable":  func(*Env) int { return 0 },
		"disown":  func(*Env) int { return 0 },
		"times":   func(e *Env) int { e.Print("0m0.012s 0m0.004s\n0m0.031s 0m0.019s\n"); return 0 },
	}
}

func builtinCd(e *Env) int {
	s := e.sh
	target := s.home
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
	n, err := s.fs.Stat(s.user, p)
	if err != nil {
		fmt.Fprintf(e.Stderr, "-bash: cd: %s: %s\n", target, err)
		return 1
	}
	if !n.IsDir() {
		fmt.Fprintf(e.Stderr, "-bash: cd: %s: Not a directory\n", target)
		return 1
	}
	if !vfs.CanAccess(n, s.user, 1) {
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
		out, stop = unescape(out)
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
func unescape(s string) (string, bool) {
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
		case '0':
			j := i + 1
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint("0"+s[i+1:j], 8, 8)
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
		out, used := sprintf(format, args)
		e.Print(out)
		if used == 0 || used >= len(args) {
			break
		}
		args = args[used:]
	}
	return 0
}

// sprintf implements the subset of printf(1) formats used in practice.
func sprintf(format string, args []string) (string, int) {
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
		if c == '\\' {
			s, _ := unescape(format[i : i+2])
			b.WriteString(s)
			i++
			continue
		}
		if c != '%' || i+1 >= len(format) {
			b.WriteByte(c)
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
			s, _ := unescape(next())
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

func builtinExport(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	if len(args) == 0 || (len(args) == 1 && args[0] == "-p") {
		for _, kv := range s.sortedVars(true) {
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

func builtinHistory(e *Env) int {
	o := getopt(e.Args[1:])
	if o.has("c") {
		e.sh.history = nil
		return 0
	}
	h := e.sh.history
	start := 0
	if len(o.pos) > 0 {
		if n, err := strconv.Atoi(o.pos[0]); err == nil && n < len(h) {
			start = len(h) - n
		}
	}
	for i := start; i < len(h); i++ {
		e.Printf("%5d  %s\n", i+1, h[i])
	}
	return 0
}

func builtinExit(e *Env) int {
	s := e.sh
	code := s.status
	if len(e.Args) > 1 {
		if n, err := strconv.Atoi(e.Args[1]); err == nil {
			code = n & 0xff
		}
	}
	if s.depth > 0 {
		// exit inside a script ends the script only.
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
	data, err := s.fs.ReadFile(s.user, p)
	if err != nil {
		fmt.Fprintf(e.Stderr, "-bash: %s: %s\n", e.Args[1], err)
		return 1
	}
	// .bashrc returns early in non-interactive shells; skip it entirely
	// rather than interpreting case statements we do not support.
	if strings.HasSuffix(p, "/.bashrc") || strings.HasSuffix(p, "/.profile") {
		return 0
	}
	return s.runScript(&Env{Ctx: e.Ctx, Args: e.Args[1:], Stdin: e.Stdin, Stdout: e.Stdout, Stderr: e.Stderr, sh: s}, p, data)
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

func builtinSet(e *Env) int {
	if len(e.Args) == 1 {
		for _, kv := range e.sh.sortedVars(false) {
			e.Printf("%s\n", kv)
		}
	}
	return 0
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
			_, err := s.fs.Stat(s.user, p)
			return err == nil
		case "-f":
			n, err := s.fs.Stat(s.user, p)
			return err == nil && !n.IsDir()
		case "-d":
			n, err := s.fs.Stat(s.user, p)
			return err == nil && n.IsDir()
		case "-L", "-h":
			n, err := s.fs.Lstat(s.user, p)
			return err == nil && n.IsLink()
		case "-s":
			n, err := s.fs.Stat(s.user, p)
			return err == nil && n.Size() > 0
		case "-r", "-w", "-x":
			n, err := s.fs.Stat(s.user, p)
			want := map[string]uint32{"-r": 4, "-w": 2, "-x": 1}[a[0]]
			return err == nil && vfs.CanAccess(n, s.user, fsMode(want))
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

func builtinRead(e *Env) int {
	o := getopt(e.Args[1:], "p", "t", "n", "d", "u")
	prompt, _ := o.val("p")
	var line string
	if r, ok := e.Stdin.(*ttyReader); ok {
		l, err := r.s.term.ReadLine(prompt, !o.has("s"))
		if err != nil {
			return 1
		}
		r.s.log.Event("stdin", "line", l)
		line = l
	} else {
		var b [1]byte
		var sb strings.Builder
		for {
			n, err := e.Stdin.Read(b[:])
			if n == 0 || err != nil {
				if sb.Len() == 0 {
					return 1
				}
				break
			}
			if b[0] == '\n' {
				break
			}
			sb.WriteByte(b[0])
		}
		line = sb.String()
	}
	names := o.pos
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

func builtinEval(e *Env) int {
	return e.sh.execString(e.Ctx, strings.Join(e.Args[1:], " "), e.Stdin, e.Stdout, e.Stderr)
}

func builtinExec(e *Env) int {
	if len(e.Args) < 2 {
		return 0
	}
	code := e.sh.run(e.Ctx, e.Args[1:], e.Stdin, e.Stdout, e.Stderr)
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
	return e.sh.run(e.Ctx, args, e.Stdin, e.Stdout, e.Stderr)
}

func builtinKill(e *Env) int {
	args := e.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(e.Stderr, "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]")
		return 2
	}
	if args[0] == "-l" {
		e.Print(" 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n 6) SIGABRT\t 7) SIGBUS\t 8) SIGFPE\t 9) SIGKILL\t10) SIGUSR1\n11) SIGSEGV\t12) SIGUSR2\t13) SIGPIPE\t14) SIGALRM\t15) SIGTERM\n")
		return 0
	}
	status := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		pid, err := strconv.Atoi(a)
		if err != nil {
			fmt.Fprintf(e.Stderr, "-bash: kill: %s: arguments must be process or job IDs\n", a)
			status = 1
			continue
		}
		if !processExists(e.sh, pid) {
			fmt.Fprintf(e.Stderr, "-bash: kill: (%d) - No such process\n", pid)
			status = 1
		} else if e.sh.uid != 0 {
			fmt.Fprintf(e.Stderr, "-bash: kill: (%d) - Operation not permitted\n", pid)
			status = 1
		}
	}
	return status
}

func builtinUlimit(e *Env) int {
	if len(e.Args) > 1 && e.Args[1] == "-a" {
		e.Print("real-time non-blocking time  (microseconds, -R) unlimited\ncore file size              (blocks, -c) 0\ndata seg size               (kbytes, -d) unlimited\nfile size                   (blocks, -f) unlimited\nmax locked memory           (kbytes, -l) 500204\nmax memory size             (kbytes, -m) unlimited\nopen files                          (-n) 1024\nstack size                  (kbytes, -s) 8192\ncpu time                   (seconds, -t) unlimited\nmax user processes                  (-u) 15541\nvirtual memory              (kbytes, -v) unlimited\n")
		return 0
	}
	if len(e.Args) > 1 && e.Args[1] == "-n" {
		e.Print("1024\n")
		return 0
	}
	e.Print("unlimited\n")
	return 0
}

func builtinHelp(e *Env) int {
	e.Print(`GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type ` + "`help'" + ` to see this list.

 alias [-p] [name[=value] ... ]       history [-c] [-d offset] [n]
 cd [-L|[-P [-e]] [-@]] [dir]         kill [-s sigspec | -n signum] pid
 command [-pVv] command [arg ...]     pwd [-LP]
 echo [-neE] [arg ...]                read [-ers] [-p prompt] [name ...]
 eval [arg ...]                       set [-abefhkmnptuvxBCEHPT] [arg ...]
 exec [-cl] [-a name] [command]       source filename [arguments]
 exit [n]                             test [expr]
 export [-fn] [name[=value] ...]      type [-afptP] name [name ...]
 false                                unset [-f] [-v] [-n] [name ...]
`)
	return 0
}

func isShellName(n string) bool {
	switch n[strings.LastIndexByte(n, '/')+1:] {
	case "sh", "bash", "dash", "zsh", "ash":
		return true
	}
	return false
}

package commands

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "awk", Aliases: []string{"gawk"}, Run: cmdAwk},
	)
}

// cmdAwk supports the overwhelmingly common one-liners: printing fields,
// optionally with a regex filter and -F separator, plus NR/NF and END{print NR}.
func cmdAwk(e *shell.Env) int {
	o := e.Flags("F", "v", "f")
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "usage: awk [POSIX or GNU style options] -f progfile [--] file ...\nusage: awk [POSIX or GNU style options] [--] 'program' file ...")
		return 2
	}
	prog := strings.TrimSpace(o.Args[0])
	data, status := e.ReadFiles(o.Args[1:])
	sep, hasSep := o.Value("F")
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
				s, _ := shell.Unescape(strings.Trim(a, `"`))
				parts = append(parts, s)
			default:
				parts = append(parts, a)
			}
		}
		if strings.HasPrefix(stmt, "printf") {
			out, _ := shell.Sprintf(parts[0], parts[1:])
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

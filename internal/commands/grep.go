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
		shell.Command{Name: "grep", Aliases: []string{"egrep", "fgrep"}, Usage: "[-HhnlLoqvsriwFE] [-m N] [-A/B/C N] PATTERN/-e PATTERN... [FILE]...", Run: cmdGrep},
	)
}

func cmdGrep(e *shell.Env) int {
	o := e.Flags("e", "m", "A", "B", "C", "color", "colour", "max-count", "regexp")
	pats := []string{}
	if v, ok := o.Value("e", "regexp"); ok {
		pats = append(pats, v)
	}
	files := o.Args
	if len(pats) == 0 {
		if len(files) == 0 {
			return e.Usage()
		}
		pats = append(pats, strings.Split(files[0], "\n")...)
		files = files[1:]
	}
	expr := ""
	for i, p := range pats {
		if o.Has("F", "fixed-strings") {
			p = regexp.QuoteMeta(p)
		} else if !o.Has("E", "P", "extended-regexp") || e.Args[0] == "egrep" {
			// Basic regex: \| \( \) are operators, bare | ( ) are literal.
			p = basicToExtended(p)
		}
		if o.Has("w", "word-regexp") {
			p = `\b(?:` + p + `)\b`
		}
		if o.Has("x", "line-regexp") {
			p = `^(?:` + p + `)$`
		}
		if i > 0 {
			expr += "|"
		}
		expr += "(?:" + p + ")"
	}
	if o.Has("i", "ignore-case") {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		fmt.Fprintf(e.Stderr, "grep: bad regex '%s'\n", expr)
		return 2
	}
	invert := o.Has("v", "invert-match")
	maxCount := -1
	if v, ok := o.Value("m", "max-count"); ok {
		maxCount, _ = strconv.Atoi(v)
	}
	color := e.Color()
	if c, ok := o.Value("color", "colour"); ok {
		color = c == "always" || (c == "auto" && e.Color())
	} else {
		color = false
	}
	recursive := o.Has("r", "R", "recursive")
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
	showName := (len(files) > 1 || recursive) && !o.Has("h", "no-filename")
	if o.Has("H", "with-filename") {
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
			if o.Has("q", "quiet", "silent", "c", "count", "l", "files-with-matches") {
				continue
			}
			out := line
			if o.Has("o", "only-matching") && !invert {
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
			if o.Has("n", "line-number") {
				prefix += strconv.Itoa(i+1) + ":"
			}
			e.Printf("%s%s\n", prefix, out)
		}
		if o.Has("c", "count") {
			if showName {
				e.Printf("%s:", name)
			}
			e.Printf("%d\n", count)
		}
		if o.Has("l", "files-with-matches") && count > 0 {
			e.Printf("%s\n", name)
		}
	}
	if len(files) == 0 {
		grepText("(standard input)", e.ReadStdin())
	}
	for _, f := range files {
		n, err := e.FS.Stat(f)
		if err == nil && n.IsDir() {
			if !o.Has("s", "no-messages") {
				fmt.Fprintf(e.Stderr, "grep: %s: Is a directory\n", f)
			}
			status = 2
			continue
		}
		data, err := e.FS.ReadFile(f)
		if err != nil {
			if !o.Has("s", "no-messages") {
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

func walkFiles(e *shell.Env, root string) []string {
	var out []string
	var walk func(p, shown string)
	walk = func(p, shown string) {
		n, err := e.FS.Stat(p)
		if err != nil {
			return
		}
		if !n.IsDir() {
			out = append(out, shown)
			return
		}
		children, err := e.FS.ReadDir(p)
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
	walk(e.FS.Abs(root), root)
	return out
}

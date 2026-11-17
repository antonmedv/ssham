package commands

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "sed", Run: cmdSed},
	)
}

// cmdSed supports s/// substitutions (with g and i flags), line deletion and
// printing by number or regex, -n and -i.
func cmdSed(e *shell.Env) int {
	o := e.Flags("e", "expression")
	var scripts []string
	if v, ok := o.Value("e", "expression"); ok {
		scripts = append(scripts, v)
	}
	files := o.Args
	if len(scripts) == 0 {
		if len(files) == 0 {
			fmt.Fprintln(e.Stderr, "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...")
			return 1
		}
		scripts = append(scripts, files[0])
		files = files[1:]
	}
	quiet := o.Has("n", "quiet", "silent")
	apply := func(text string) (string, error) {
		lines := splitLines(text)
		var out strings.Builder
	run:
		for _, script := range scripts {
			for _, cmd := range strings.Split(script, ";") {
				cmd = strings.TrimSpace(cmd)
				if cmd == "" {
					continue
				}
				var err error
				lines, err = sedApply(cmd, lines, quiet, &out)
				if errors.Is(err, errQuit) {
					break run
				}
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
	if o.Has("i", "in-place") {
		status := 0
		for _, f := range files {
			p := e.FS.Abs(f)
			data, err := e.FS.ReadFile(p)
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
			if err := e.FS.WriteFile(p, []byte(res)); err != nil {
				e.Errorf("couldn't open temporary file %s: %s", f, err)
				status = 4
			}
		}
		return status
	}
	var b strings.Builder
	status := 0
	for _, f := range files {
		data, err := e.FS.ReadFile(f)
		if err != nil {
			e.Errorf("can't read %s: %s", f, err)
			status = 2
			continue
		}
		b.Write(data)
	}
	if len(files) == 0 {
		b.WriteString(e.ReadStdin())
	}
	res, err := apply(b.String())
	if err != nil {
		e.Errorf("-e expression #1, char 1: %s", err)
		return 1
	}
	e.Print(res)
	return status
}

// errQuit stops the script after the q command.
var errQuit = errors.New("quit")

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
	case 'q':
		// Print up to the first matching line, then stop.
		for i, l := range lines {
			if match(i, l) {
				return lines[:i+1], errQuit
			}
		}
		return lines, nil
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
		pat, repl, flags := basicToExtended(parts[0]), parts[1], parts[2]
		if strings.Contains(flags, "I") || strings.Contains(flags, "i") {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
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

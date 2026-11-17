package commands

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "bash", Aliases: []string{"sh", "dash"}, Run: cmdShell},
		shell.Command{Name: "python3", Aliases: []string{"perl"}, Run: cmdInterpreter},
		shell.Command{Name: "vi", Aliases: []string{"vim", "nano"}, Run: cmdEditor},
		shell.Command{Name: "env", Aliases: []string{"printenv"}, Run: cmdEnv},
		shell.Command{Name: "nohup", Run: cmdNohup},
		shell.Command{Name: "timeout", Run: cmdTimeout},
		shell.Command{Name: "xargs", Run: cmdXargs},
		shell.Command{Name: "sleep", Run: cmdSleep},
		shell.Command{Name: "clear", Aliases: []string{"reset"}, Run: cmdClear},
	)
}

// cmdShell handles sh/bash: -c strings, script files, and nested
// interactive shells.
// cmdShell handles sh and bash: -c strings, script files, scripts piped in
// (curl ... | sh), and nested interactive shells.
func cmdShell(e *shell.Env) int {
	args := e.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-c" {
		args = args[1:]
	}
	switch {
	case len(args) >= 2 && args[0] == "-c":
		e.Log(audit.ExecInline, "shell", e.Args[0], "script", truncate(args[1], 8192))
		// bash -c 'script' name a b: $0 is name, $1 is a, ...
		argv := args[2:]
		if len(argv) == 0 {
			argv = []string{e.Args[0]}
		}
		return e.RunScript(args[1], argv...)
	case len(args) >= 1:
		return e.RunFile(args[0], args...)
	case !e.Interactive():
		script := e.ReadStdin()
		e.Log(audit.ExecInline, "shell", e.Args[0], "script", truncate(script, 8192))
		return e.RunScript(script)
	}
	e.Login(e.User(), "")
	return 0
}

func cmdInterpreter(e *shell.Env) int {
	args := e.Args[1:]
	for i, a := range args {
		if a == "-c" || a == "-e" {
			code := ""
			if i+1 < len(args) {
				code = args[i+1]
			}
			e.Log(audit.ExecInline, "interpreter", e.Args[0], "script", truncate(code, 8192))
			return 0
		}
		if a == "-V" || a == "--version" || (a == "-v" && e.Args[0] == "perl") {
			if strings.HasPrefix(e.Args[0], "python") {
				e.Print("Python 3.12.3\n")
			} else {
				e.Print("\nThis is perl 5, version 38, subversion 2 (v5.38.2) built for x86_64-linux-gnu-thread-multi\n")
			}
			return 0
		}
	}
	if len(args) > 0 {
		if data, err := e.FS.ReadFile(args[0]); err == nil {
			e.Log(audit.ExecScript, "interpreter", e.Args[0], "path", e.FS.Abs(args[0]), "content", truncate(string(data), 8192))
			return 0
		}
		fmt.Fprintf(e.Stderr, "%s: can't open file '%s': [Errno 2] No such file or directory\n", e.Args[0], e.FS.Abs(args[0]))
		return 2
	}
	if !e.Interactive() {
		e.Log(audit.ExecInline, "interpreter", e.Args[0], "script", truncate(e.ReadStdin(), 8192))
		return 0
	}
	if strings.HasPrefix(e.Args[0], "python") {
		e.Print("Python 3.12.3 (main, Sep 11 2024, 14:17:37) [GCC 13.2.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n")
		for {
			line, err := e.ReadLine(">>> ", true)
			if err != nil {
				e.Print("\n")
				return 0
			}
			e.Log(audit.Stdin, "interpreter", "python", "line", line)
			if l := strings.TrimSpace(line); l == "exit()" || l == "quit()" {
				return 0
			} else if l != "" {
				e.Printf("Traceback (most recent call last):\n  File \"<stdin>\", line 1, in <module>\nModuleNotFoundError: No module named '%s'\n", strings.Fields(strings.NewReplacer("(", " ", ".", " ").Replace(l))[0])
			}
		}
	}
	return 0
}

func cmdEditor(e *shell.Env) int {
	if len(e.Args) > 1 {
		e.Log(audit.EditorOpen, "editor", e.Args[0], "path", e.FS.Abs(e.Args[len(e.Args)-1]))
	}
	if e.Session().Term == "" {
		fmt.Fprintf(e.Stderr, "Error opening terminal: unknown.\n")
		return 1
	}
	fmt.Fprintf(e.Stderr, "Error opening terminal: %s.\n", e.Session().Term)
	return 1
}

// cmdEnv prints the environment, or runs a command: env VAR=x cmd.
func cmdEnv(e *shell.Env) int {
	args := e.Args[1:]
	var vars []string
	for len(args) > 0 && (strings.HasPrefix(args[0], "-") || strings.Contains(args[0], "=")) {
		if strings.Contains(args[0], "=") {
			vars = append(vars, args[0])
		}
		args = args[1:]
	}
	if len(args) > 0 && e.Args[0] == "env" {
		return e.RunWithVars(vars, args...)
	}
	env := e.Environ()
	if e.Args[0] == "printenv" && len(args) > 0 {
		status := 1
		for _, name := range args {
			for _, kv := range env {
				if v, ok := strings.CutPrefix(kv, name+"="); ok {
					e.Printf("%s\n", v)
					status = 0
				}
			}
		}
		return status
	}
	for _, kv := range env {
		e.Printf("%s\n", kv)
	}
	return 0
}

func cmdNohup(e *shell.Env) int {
	if len(e.Args) < 2 {
		fmt.Fprintln(e.Stderr, "nohup: missing operand")
		return 125
	}
	if e.IsTTY() {
		fmt.Fprintln(e.Stderr, "nohup: ignoring input and appending output to 'nohup.out'")
	}
	return e.RunWithStdin(strings.NewReader(""), e.Args[1:]...)
}

func cmdTimeout(e *shell.Env) int {
	args := e.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	if len(args) < 2 {
		fmt.Fprintln(e.Stderr, "timeout: missing operand")
		return 125
	}
	return e.Run(args[1:]...)
}

func cmdXargs(e *shell.Env) int {
	o := e.Flags("n", "I", "d", "P", "L")
	args := e.Args[1:]
	// Find where the command begins: the first positional in o.Args.
	cmd := []string{"echo"}
	if len(o.Args) > 0 {
		for i, a := range args {
			if a == o.Args[0] {
				cmd = args[i:]
				break
			}
		}
	}
	items := strings.Fields(e.ReadStdin())
	if repl, ok := o.Value("I"); ok {
		status := 0
		for _, item := range items {
			var argv []string
			for _, a := range cmd {
				argv = append(argv, strings.ReplaceAll(a, repl, item))
			}
			status = e.RunWithStdin(strings.NewReader(""), argv...)
		}
		return status
	}
	if len(items) == 0 && o.Has("r", "no-run-if-empty") {
		return 0
	}
	return e.RunWithStdin(strings.NewReader(""), append(append([]string{}, cmd...), items...)...)
}

func cmdSleep(e *shell.Env) int {
	var total time.Duration
	for _, a := range e.Args[1:] {
		mult := time.Second
		switch {
		case strings.HasSuffix(a, "m"):
			mult, a = time.Minute, strings.TrimSuffix(a, "m")
		case strings.HasSuffix(a, "h"):
			mult, a = time.Hour, strings.TrimSuffix(a, "h")
		case strings.HasSuffix(a, "s"):
			a = strings.TrimSuffix(a, "s")
		}
		f, err := strconv.ParseFloat(a, 64)
		if err != nil {
			e.Errorf("invalid time interval '%s'", a)
			return 1
		}
		total += time.Duration(f * float64(mult))
	}
	if len(e.Args) == 1 {
		fmt.Fprintln(e.Stderr, "sleep: missing operand\nTry 'sleep --help' for more information.")
		return 1
	}
	if !e.Sleep(total) {
		return 130
	}
	return 0
}

func cmdClear(e *shell.Env) int {
	e.Print("\x1b[H\x1b[2J\x1b[3J")
	return 0
}

package commands

import (
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "sh", Aliases: []string{"ash"}, Usage: "[-/+OPTIONS] [-/+o OPT]... [-c 'SCRIPT' [ARG0 [ARGS]] / FILE [ARGS] / -s [ARGS]]", Run: cmdShell},
		shell.Command{Name: "env", Dir: "/usr/bin", Usage: "[-iu] [-] [NAME=VALUE]... [PROG ARGS]", Run: cmdEnv},
		shell.Command{Name: "xargs", Dir: "/usr/bin", Usage: "[OPTIONS] [PROG ARGS]", Run: cmdXargs},
		shell.Command{Name: "sleep", Usage: "[N]...", Run: cmdSleep},
		shell.Command{Name: "clear", Dir: "/usr/bin", Usage: "", Run: cmdClear},
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
		// sh -c 'script' name a b: $0 is name, $1 is a, ...
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
	if len(args) > 0 {
		return e.RunWithVars(vars, args...)
	}
	for _, kv := range append(e.Environ(), vars...) {
		e.Printf("%s\n", kv)
	}
	return 0
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
	if len(e.Args) == 1 {
		return e.Usage()
	}
	var total time.Duration
	for _, a := range e.Args[1:] {
		mult := time.Second
		switch {
		case strings.HasSuffix(a, "m"):
			mult, a = time.Minute, strings.TrimSuffix(a, "m")
		case strings.HasSuffix(a, "h"):
			mult, a = time.Hour, strings.TrimSuffix(a, "h")
		case strings.HasSuffix(a, "d"):
			mult, a = 24*time.Hour, strings.TrimSuffix(a, "d")
		case strings.HasSuffix(a, "s"):
			a = strings.TrimSuffix(a, "s")
		}
		f, err := strconv.ParseFloat(a, 64)
		if err != nil {
			e.Errorf("invalid number '%s'", a)
			return 1
		}
		total += time.Duration(f * float64(mult))
	}
	if !e.Sleep(total) {
		return 130
	}
	return 0
}

func cmdClear(e *shell.Env) int {
	e.Print("\x1b[H\x1b[J")
	return 0
}

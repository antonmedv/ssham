package shell

import (
	"fmt"
	"sort"
	"strings"
)

// builtin is a command BusyBox ash implements itself.
type builtin struct {
	run func(*Env) int
	// dir is set for builtins that are also BusyBox applets (echo, test,
	// ...): where the applet's link lives.
	dir string
}

var builtins map[string]builtin

func init() {
	nop := func(*Env) int { return 0 }
	builtins = map[string]builtin{
		// builtins_basic.go
		"cd":     {run: builtinCd},
		"chdir":  {run: builtinCd},
		"pwd":    {run: builtinPwd, dir: "/bin"},
		"echo":   {run: builtinEcho, dir: "/bin"},
		"printf": {run: builtinPrintf, dir: "/usr/bin"},
		"test":   {run: builtinTest, dir: "/usr/bin"},
		"[":      {run: builtinTest, dir: "/usr/bin"},
		"[[":     {run: builtinTest, dir: "/usr/bin"},
		"true":   {run: nop, dir: "/bin"},
		"false":  {run: func(*Env) int { return 1 }, dir: "/bin"},
		":":      {run: nop},

		// builtins_vars.go
		"export":   {run: builtinExport},
		"readonly": {run: builtinExport},
		"unset":    {run: builtinUnset},
		"alias":    {run: builtinAlias},
		"unalias":  {run: builtinUnalias},
		"set":      {run: builtinSet},
		"read":     {run: builtinRead},
		"shift":    {run: builtinShift},
		"let":      {run: builtinLet},

		// builtins_flow.go
		"exit":     {run: builtinExit},
		"return":   {run: builtinReturn},
		"break":    {run: builtinBreak},
		"continue": {run: builtinBreak},
		"source":   {run: builtinSource},
		".":        {run: builtinSource},
		"eval":     {run: builtinEval},
		"exec":     {run: builtinExec},
		"command":  {run: builtinCommand},
		"type":     {run: builtinType},
		"history":  {run: builtinHistory},

		// Accepted and ignored.
		"jobs": {run: builtinJobs}, "wait": {run: builtinWait}, "fg": {run: builtinFg}, "bg": {run: builtinFg},
		"trap": {run: builtinTrap}, "getopts": {run: builtinGetopts}, "hash": {run: nop},
		"local": {run: builtinLocal},

		// Fixed output.
		"umask":  {run: builtinUmask},
		"times":  {run: printing("0m 0.01s 0m 0.02s\n0m 0.00s 0m 0.00s\n")},
		"ulimit": {run: builtinUlimit},
		"help":   {run: builtinHelp},
	}
}

func printing(s string) func(*Env) int {
	return func(e *Env) int {
		e.Print(s)
		return 0
	}
}

func builtinUmask(e *Env) int {
	e.Print("0022\n")
	return 0
}

func builtinUlimit(e *Env) int {
	switch {
	case len(e.Args) > 1 && e.Args[1] == "-a":
		e.Print(ulimitAll)
	case len(e.Args) > 1 && e.Args[1] == "-n":
		e.Print("1024\n")
	case len(e.Args) > 1 && e.Args[1] == "-s":
		e.Print("2048\n")
	default:
		e.Print("unlimited\n")
	}
	return 0
}

const ulimitAll = `-f: file size (blocks)             unlimited
-t: cpu time (seconds)             unlimited
-d: data seg size (kb)             unlimited
-s: stack size (kb)                2048
-c: core file size (blocks)        0
-m: resident set size (kb)         unlimited
-l: locked memory (kb)             64
-p: processes                      447
-n: file descriptors               1024
-v: address space (kb)             unlimited
-w: locks                          unlimited
-e: scheduling priority            0
-r: real-time priority             0
`

// builtinHelp lists the builtins, as ash's help does.
func builtinHelp(e *Env) int {
	names := []string{"kill"} // ash's kill builtin is the kill applet here
	for name := range builtins {
		names = append(names, name)
	}
	sort.Strings(names)
	e.Print("Built-in commands:\n------------------\n")
	line := "\t"
	for _, n := range names {
		if len(line)+len(n) > 66 {
			e.Printf("%s\n", strings.TrimRight(line, " "))
			line = "\t"
		}
		line += n + " "
	}
	e.Printf("%s\n", strings.TrimRight(line, " "))
	return 0
}

// sh reports a builtin's error the way ash does: "sh: name: message".
func sh(e *Env, format string, a ...any) {
	fmt.Fprintf(e.Stderr, "sh: "+format+"\n", a...)
}

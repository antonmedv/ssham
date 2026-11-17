package shell

// builtin is a command implemented by the shell itself, because it needs
// the shell's state (cd, export, exit, ...) or because bash has it built in.
type builtin struct {
	run func(*Env) int
	// binary means a program with the same name also exists in
	// /usr/bin (e.g. /usr/bin/echo).
	binary bool
}

var builtins map[string]builtin

func init() {
	nop := func(*Env) int { return 0 }
	builtins = map[string]builtin{
		// builtins_basic.go
		"cd":     {run: builtinCd},
		"pwd":    {run: builtinPwd, binary: true},
		"echo":   {run: builtinEcho, binary: true},
		"printf": {run: builtinPrintf, binary: true},
		"test":   {run: builtinTest, binary: true},
		"[":      {run: builtinTest, binary: true},
		"true":   {run: nop, binary: true},
		"false":  {run: func(*Env) int { return 1 }, binary: true},
		":":      {run: nop},

		// builtins_vars.go
		"export":  {run: builtinExport},
		"unset":   {run: builtinUnset},
		"alias":   {run: builtinAlias},
		"unalias": {run: builtinUnalias},
		"set":     {run: builtinSet},
		"read":    {run: builtinRead},

		// builtins_flow.go
		"exit":    {run: builtinExit},
		"logout":  {run: builtinExit},
		"source":  {run: builtinSource},
		".":       {run: builtinSource},
		"eval":    {run: builtinEval},
		"exec":    {run: builtinExec},
		"command": {run: builtinCommand},
		"builtin": {run: builtinCommand},
		"type":    {run: builtinType},
		"history": {run: builtinHistory},

		// Accepted and ignored.
		"jobs": {run: nop}, "wait": {run: nop}, "shopt": {run: nop}, "hash": {run: nop},
		"trap": {run: nop}, "enable": {run: nop}, "disown": {run: nop},

		// Fixed output.
		"umask":  {run: builtinUmask},
		"times":  {run: printing("0m0.012s 0m0.004s\n0m0.031s 0m0.019s\n")},
		"ulimit": {run: builtinUlimit},
		"help":   {run: printing(helpText)},
	}
}

func printing(s string) func(*Env) int {
	return func(e *Env) int {
		e.Print(s)
		return 0
	}
}

func builtinUmask(e *Env) int {
	if e.User().IsRoot() {
		e.Print("0022\n")
	} else {
		e.Print("0002\n")
	}
	return 0
}

func builtinUlimit(e *Env) int {
	switch {
	case len(e.Args) > 1 && e.Args[1] == "-a":
		e.Print(ulimitAll)
	case len(e.Args) > 1 && e.Args[1] == "-n":
		e.Print("1024\n")
	default:
		e.Print("unlimited\n")
	}
	return 0
}

const ulimitAll = `real-time non-blocking time  (microseconds, -R) unlimited
core file size              (blocks, -c) 0
data seg size               (kbytes, -d) unlimited
file size                   (blocks, -f) unlimited
max locked memory           (kbytes, -l) 500204
max memory size             (kbytes, -m) unlimited
open files                          (-n) 1024
stack size                  (kbytes, -s) 8192
cpu time                   (seconds, -t) unlimited
max user processes                  (-u) 15541
virtual memory              (kbytes, -v) unlimited
`

const helpText = `GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)
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
`

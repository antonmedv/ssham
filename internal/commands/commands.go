// Package commands holds the simulated programs: ls, cat, wget, sudo, ...
//
// Each file registers its commands in an init function. To add a command,
// write a func(*shell.Env) int and register it:
//
//	func init() {
//		register(shell.Command{Name: "uptime", Run: cmdUptime})
//	}
//
// Registering also installs a fake binary (in /usr/bin unless Dir says
// otherwise), so `which`, tab completion and `ls /usr/bin` all agree.
// Then add a transcript test in testdata/.
package commands

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/shell"
)

var registry = shell.NewRegistry()

func register(cmds ...shell.Command) { registry.Add(cmds...) }

// Registry returns every simulated command.
func Registry() *shell.Registry { return registry }

func init() {
	// Installed programs we don't simulate: they run and print nothing.
	register(
		shell.Command{Name: "diff"},
		shell.Command{Name: "lsattr"},
		shell.Command{Name: "pkill"},
		shell.Command{Name: "killall"},
		shell.Command{Name: "sshd", Dir: "/usr/sbin"},
	)
}

// truncate shortens s for the audit log.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// isShellName reports whether n names a shell program.
func isShellName(n string) bool {
	switch n[strings.LastIndexByte(n, '/')+1:] {
	case "sh", "bash", "dash", "zsh", "ash":
		return true
	}
	return false
}

// uidOf returns a user's numeric id as ls -n shows it.
func uidOf(e *shell.Env, name string) string {
	if u, ok := e.LookupUser(name); ok {
		return strconv.Itoa(u.UID)
	}
	return name
}

// gidOf returns a group's numeric id as ls -n shows it.
func gidOf(e *shell.Env, group string) string {
	if id := e.GroupID(group); id >= 0 {
		return strconv.Itoa(id)
	}
	return group
}

// isText reports whether data looks like text rather than a binary.
func isText(data []byte) bool {
	if len(data) > 512 {
		data = data[:512]
	}
	return !bytes.ContainsRune(data, 0)
}

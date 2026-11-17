// Package commands holds the BusyBox applets of the device: ls, cat, wget,
// ps, ... The set is small and closed on purpose: a camera has exactly
// these, and anything else is "not found".
//
// Each file registers its applets in an init function. To add one, write a
// func(*shell.Env) int and register it with BusyBox's usage text:
//
//	func init() {
//		register(shell.Command{Name: "uptime", Dir: "/usr/bin", Usage: "", Run: cmdUptime})
//	}
//
// Registering also links it to /bin/busybox in Dir, so `busybox`, `which`,
// tab completion and `ls -l /bin` all agree. Then add a transcript test in
// testdata/.
package commands

import (
	"bytes"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/shell"
)

var registry = shell.NewRegistry()

func register(cmds ...shell.Command) { registry.Add(cmds...) }

// Registry returns every applet.
func Registry() *shell.Registry { return registry }

func init() {
	register(shell.Command{
		Name: "busybox",
		Usage: `[function [arguments]...]
   or: busybox --list[-full]
   or: function [arguments]...`,
		Run: cmdBusybox,
	})
}

// cmdBusybox is the multi-call binary itself: `busybox ls` runs ls, and
// with no arguments it lists the applets.
func cmdBusybox(e *shell.Env) int {
	if len(e.Args) < 2 {
		e.Printf(`%s multi-call binary.
BusyBox is copyrighted by many authors between 1998-2015.
Licensed under GPLv2. See source distribution for detailed
copyright notices.

Usage: busybox [function [arguments]...]
   or: busybox --list[-full]
   or: busybox --install [-s] [DIR]
   or: function [arguments]...

	BusyBox is a multi-call binary that combines many common Unix
	utilities into a single executable.  Most people will create a
	link to busybox for each function they wish to use and BusyBox
	will act like whatever it was invoked as.

Currently defined functions:
%s
`, rootfs.BusyBox, wrapList(appletNames(e), 70))
		return 0
	}
	switch e.Args[1] {
	case "--list":
		for _, name := range appletNames(e) {
			e.Printf("%s\n", name)
		}
		return 0
	case "--list-full":
		applets := e.Applets()
		var full []string
		for _, name := range appletNames(e) {
			full = append(full, strings.TrimPrefix(path.Join(applets[name], name), "/"))
		}
		sort.Strings(full)
		for _, f := range full {
			e.Printf("%s\n", f)
		}
		return 0
	}
	if strings.HasPrefix(e.Args[1], "-") {
		return e.Usage()
	}
	return e.RunApplet(e.Args[1:]...)
}

// appletNames lists the applets, without busybox itself.
func appletNames(e *shell.Env) []string {
	var names []string
	for name := range e.Applets() {
		if name != "busybox" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// wrapList joins names with ", " into tab-indented lines of at most width
// columns, as BusyBox lists its functions.
func wrapList(names []string, width int) string {
	var b strings.Builder
	line := "\t"
	for i, n := range names {
		item := n
		if i < len(names)-1 {
			item += ","
		}
		if len(line)+len(item)+1 > width && line != "\t" {
			b.WriteString(strings.TrimRight(line, " ") + "\n")
			line = "\t"
		}
		line += item + " "
	}
	b.WriteString(strings.TrimRight(line, " "))
	return b.String()
}

// truncate shortens s for the audit log.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// isText reports whether data looks like text rather than a binary.
func isText(data []byte) bool {
	if len(data) > 512 {
		data = data[:512]
	}
	return !bytes.ContainsRune(data, 0)
}

// uidOf returns a user's numeric id, as ls -n shows it.
func uidOf(e *shell.Env, name string) string {
	if u, ok := e.LookupUser(name); ok {
		return strconv.Itoa(u.UID)
	}
	return name
}

// gidOf returns a group's numeric id, as ls -n shows it.
func gidOf(e *shell.Env, group string) string {
	if id := e.GroupID(group); id >= 0 {
		return strconv.Itoa(id)
	}
	return group
}

package commands

import (
	"fmt"
	"hash/fnv"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/shell"
	"github.com/antonmedv/ssham/internal/vfs"
)

func init() {
	register(
		shell.Command{Name: "ls", Usage: "[-1AaCxdLHRFplinshrSXvctu] [-w WIDTH] [FILE]...", Run: cmdLs},
	)
}

func cmdLs(e *shell.Env) int {
	o := e.Flags("color", "w", "sort", "time-style")
	long := o.Has("l", "n", "g", "o")
	all := o.Has("a", "all")
	almost := o.Has("A", "almost-all")
	dirOnly := o.Has("d", "directory")
	one := o.Has("1")
	recursive := o.Has("R", "recursive")
	classify := o.Has("F", "classify")
	// BusyBox colors by default on a terminal; --color alone means always.
	color := e.IsTTY()
	if c, ok := o.Value("color"); ok {
		color = c == "" || c == "always" || c == "yes" || c == "force" || ((c == "auto" || c == "tty" || c == "if-tty") && e.IsTTY())
	}
	targets := o.Args
	if len(targets) == 0 {
		targets = []string{"."}
	}

	sortEntries := func(ents []lsEntry) {
		switch {
		case o.Has("t"):
			sort.SliceStable(ents, func(i, j int) bool { return ents[i].node.ModTime.After(ents[j].node.ModTime) })
		case o.Has("S"):
			sort.SliceStable(ents, func(i, j int) bool { return ents[i].node.Size() > ents[j].node.Size() })
		default:
			// No locale on the device: plain byte order, so TZ sorts
			// before dropbear.
			sort.SliceStable(ents, func(i, j int) bool { return ents[i].name < ents[j].name })
		}
		if o.Has("r") {
			for i, j := 0, len(ents)-1; i < j; i, j = i+1, j-1 {
				ents[i], ents[j] = ents[j], ents[i]
			}
		}
	}

	display := func(ent lsEntry) string {
		name := ent.name
		if color {
			name = lsColor(ent.node, name)
		}
		if classify {
			switch {
			case ent.node.IsDir():
				name += "/"
			case ent.node.IsLink():
				name += "@"
			case ent.node.Mode.Perm()&0o111 != 0:
				name += "*"
			}
		}
		return name
	}

	printEntries := func(ents []lsEntry, dirPath string, showTotal bool) {
		if long {
			if showTotal {
				var total int64
				for _, ent := range ents {
					if !ent.node.IsDir() {
						total += (ent.node.Size() + 1023) / 1024
					}
				}
				e.Printf("total %d\n", total)
			}
			for _, ent := range ents {
				e.Printf("%s\n", lsLong(e, ent, display(ent), o))
			}
			return
		}
		if one || !e.IsTTY() {
			for _, ent := range ents {
				if o.Has("i") {
					e.Printf("%7d ", inode(ent.path))
				}
				e.Printf("%s\n", display(ent))
			}
			return
		}
		names := make([]string, len(ents))
		plain := make([]int, len(ents))
		for i, ent := range ents {
			names[i] = display(ent)
			plain[i] = len(ent.name)
			if classify && names[i] != "" && strings.ContainsAny(names[i][len(names[i])-1:], "/@*") {
				plain[i]++
			}
			if o.Has("i") {
				names[i] = fmt.Sprintf("%7d ", inode(ent.path)) + names[i]
				plain[i] += 8
			}
		}
		e.Print(columns(names, plain, e.Width()))
	}

	var files []lsEntry
	var dirs []lsEntry
	status := 0
	for _, t := range targets {
		p := e.FS.Abs(t)
		n, err := e.FS.Lstat(p)
		if err == nil && n.IsLink() && !long {
			if tn, err2 := e.FS.Stat(p); err2 == nil {
				n = tn
			}
		}
		if err == nil && n.IsLink() && long && strings.HasSuffix(t, "/") {
			n, err = e.FS.Stat(p)
		}
		if err != nil {
			fmt.Fprintf(e.Stderr, "ls: %s: %s\n", t, err)
			status = 2
			continue
		}
		if n.IsDir() && !dirOnly {
			dirs = append(dirs, lsEntry{name: t, path: p, node: n})
		} else {
			files = append(files, lsEntry{name: t, path: p, node: n})
		}
	}
	sortEntries(files)
	if len(files) > 0 {
		printEntries(files, "", false)
	}
	var listDir func(name, p string, header bool)
	listDir = func(name, p string, header bool) {
		children, err := e.FS.ReadDir(p)
		if err != nil {
			fmt.Fprintf(e.Stderr, "ls: can't open '%s': %s\n", name, err)
			status = 2
			return
		}
		if header {
			e.Printf("%s:\n", name)
		}
		var ents []lsEntry
		if all {
			self, _ := e.FS.AsRoot().Stat(p)
			parent, _ := e.FS.AsRoot().Stat(path.Dir(p))
			ents = append(ents, lsEntry{".", p, self}, lsEntry{"..", path.Dir(p), parent})
		}
		for _, c := range children {
			if strings.HasPrefix(c.Name, ".") && !all && !almost {
				continue
			}
			ents = append(ents, lsEntry{c.Name, path.Join(p, c.Name), c})
		}
		sortEntries(ents)
		printEntries(ents, p, true)
		if recursive {
			for _, ent := range ents {
				if ent.node.IsDir() && ent.name != "." && ent.name != ".." {
					e.Print("\n")
					listDir(path.Join(name, ent.name), path.Join(p, ent.name), true)
				}
			}
		}
	}
	for i, d := range dirs {
		if i > 0 || len(files) > 0 {
			e.Print("\n")
		}
		listDir(d.name, e.FS.Abs(d.name), len(dirs)+len(files) > 1 || recursive)
	}
	return status
}

type lsEntry struct {
	name string
	path string
	node *vfs.Node
}

// lsLong formats one line of ls -l the way BusyBox does: fixed-width
// fields, not columns fitted to the content like GNU ls.
func lsLong(e *shell.Env, ent lsEntry, name string, o shell.Flags) string {
	n := ent.node
	var b strings.Builder
	if o.Has("i") {
		fmt.Fprintf(&b, "%7d ", inode(ent.path))
	}
	links := 1
	if n.IsDir() {
		links = 2
		for _, c := range n.Children {
			if c.IsDir() {
				links++
			}
		}
	}
	fmt.Fprintf(&b, "%-10s %4d ", modeString(n), links)
	owner, group := n.Owner, n.Group
	if o.Has("n") {
		owner, group = uidOf(e, owner), gidOf(e, group)
	}
	switch {
	case o.Has("g"):
		fmt.Fprintf(&b, "%-8.8s ", group)
	case o.Has("o"):
		fmt.Fprintf(&b, "%-8.8s ", owner)
	default:
		fmt.Fprintf(&b, "%-8.8s %-8.8s ", owner, group)
	}
	switch {
	case n.IsDevice():
		fmt.Fprintf(&b, "%4d, %4d ", n.Major, n.Minor)
	case o.Has("h", "human-readable"):
		fmt.Fprintf(&b, "%7s ", humanSize(n.Size()))
	default:
		fmt.Fprintf(&b, "%9d ", fileSize(ent.path, n))
	}
	b.WriteString(lsTime(e.Now().In(zone), n.ModTime.In(zone)) + " " + name)
	if n.IsLink() {
		b.WriteString(" -> " + n.Target)
	}
	return b.String()
}

// fileSize is the size ls shows. A directory's size depends on the
// filesystem: tmpfs counts 20 per entry, squashfs the names, /proc and
// jffs2 nothing.
func fileSize(p string, n *vfs.Node) int64 {
	if !n.IsDir() {
		return n.Size()
	}
	switch {
	case n.Virtual, p == "/mnt/mtd" || strings.HasPrefix(p, "/mnt/mtd/"):
		return 0
	case p == "/tmp" || p == "/var" || p == "/dev" || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/var/") || strings.HasPrefix(p, "/dev/"):
		return 40 + 20*int64(len(n.Children))
	}
	size := int64(3)
	for name := range n.Children {
		size += 8 + int64(len(name))
	}
	return size
}

// inode makes up a stable inode number for p: small on the squashfs root,
// larger on the RAM filesystems.
func inode(p string) uint64 {
	h := fnv.New32a()
	h.Write([]byte(p))
	v := uint64(h.Sum32())
	switch {
	case p == "/":
		return 1
	case strings.HasPrefix(p, "/proc/"):
		return 4026531840 + v%100000
	case strings.HasPrefix(p, "/tmp/"), strings.HasPrefix(p, "/var/"), strings.HasPrefix(p, "/dev/"):
		return 1000 + v%9000
	case strings.HasPrefix(p, "/mnt/mtd"):
		return 2 + v%300
	}
	return 2 + v%1400
}

// lsColor colors name the way BusyBox ls does: "\x1b[BOLD;COLORm".
func lsColor(n *vfs.Node, name string) string {
	attr, color := 0, 0
	switch {
	case n.IsLink():
		attr, color = 1, 36
	case n.IsDir():
		attr, color = 1, 34
	case n.IsDevice():
		attr, color = 1, 35
	case n.Mode.Perm()&0o111 != 0:
		attr, color = 1, 32
	}
	return fmt.Sprintf("\x1b[%d;%dm%s\x1b[0m", attr, color, name)
}

// modeString renders permissions the way ls -l does.
func modeString(n *vfs.Node) string {
	b := []byte("----------")
	switch {
	case n.IsDir():
		b[0] = 'd'
	case n.IsLink():
		b[0] = 'l'
	case n.IsDevice() && n.Mode&fs.ModeCharDevice != 0:
		b[0] = 'c'
	case n.IsDevice():
		b[0] = 'b'
	}
	m := n.Mode
	rwx := "rwxrwxrwx"
	for i := 0; i < 9; i++ {
		if m&(1<<uint(8-i)) != 0 {
			b[i+1] = rwx[i]
		}
	}
	if m&fs.ModeSetuid != 0 || m&0o4000 != 0 {
		if b[3] == 'x' {
			b[3] = 's'
		} else {
			b[3] = 'S'
		}
	}
	if m&fs.ModeSticky != 0 || m&0o1000 != 0 {
		if b[9] == 'x' {
			b[9] = 't'
		} else {
			b[9] = 'T'
		}
	}
	return string(b)
}

func lsTime(now, t time.Time) string {
	if now.Sub(t) >= 365*24*time.Hour/2 || t.Sub(now) >= 15*time.Minute {
		return t.Format("Jan _2  2006")
	}
	return t.Format("Jan _2 15:04")
}

func humanSize(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10)
	}
	units := "KMGTP"
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if f < 10 {
		return fmt.Sprintf("%.1f%c", f+0.05, units[i])
	}
	return fmt.Sprintf("%.0f%c", f+0.5, units[i])
}

// columns lays names out like BusyBox ls: down the columns, every column
// as wide as the longest name plus two.
func columns(names []string, widths []int, termWidth int) string {
	if len(names) == 0 {
		return ""
	}
	colW := 0
	for _, w := range widths {
		colW = max(colW, w)
	}
	colW += 2
	cols := max(termWidth/colW, 1)
	rows := (len(names) + cols - 1) / cols
	var b strings.Builder
	for r := 0; r < rows; r++ {
		pad := 0
		for c := 0; c < cols; c++ {
			i := c*rows + r
			if i >= len(names) {
				break
			}
			b.WriteString(strings.Repeat(" ", pad))
			b.WriteString(names[i])
			pad = colW - widths[i]
		}
		b.WriteByte('\n')
	}
	return b.String()
}

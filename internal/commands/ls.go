package commands

import (
	"fmt"
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
		shell.Command{Name: "ls", Aliases: []string{"dir"}, Run: cmdLs},
	)
}

func cmdLs(e *shell.Env) int {
	o := e.Flags("color", "w", "sort", "time-style")
	long := o.Has("l", "n", "g", "o")
	all := o.Has("a", "all")
	almost := o.Has("A", "almost-all")
	human := o.Has("h", "human-readable")
	dirOnly := o.Has("d", "directory")
	one := o.Has("1")
	recursive := o.Has("R", "recursive")
	classify := o.Has("F", "classify")
	color := false
	if c, ok := o.Value("color"); ok && c != "never" && c != "no" {
		color = c == "always" || e.Color()
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
			sort.SliceStable(ents, func(i, j int) bool {
				return strings.ToLower(strings.TrimLeft(ents[i].name, ".")) < strings.ToLower(strings.TrimLeft(ents[j].name, "."))
			})
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
			var total int64
			rows := make([][]string, 0, len(ents))
			for _, ent := range ents {
				n := ent.node
				total += (n.Size() + 4095) / 4096 * 4
				links := 1
				if n.IsDir() {
					links = 2
					for _, c := range n.Children {
						if c.IsDir() {
							links++
						}
					}
				}
				size := strconv.FormatInt(n.Size(), 10)
				if human {
					size = humanSize(n.Size())
				}
				owner, group := n.Owner, n.Group
				if o.Has("n") {
					owner, group = uidOf(e, owner), gidOf(e, group)
				}
				name := display(ent)
				if n.IsLink() {
					name += " -> " + n.Target
				}
				row := []string{modeString(n), strconv.Itoa(links), owner, group, size, lsTime(e.Now(), n.ModTime), name}
				if o.Has("g") {
					row = append(row[:2], row[3:]...)
				} else if o.Has("o") {
					row = append(row[:3], row[4:]...)
				}
				rows = append(rows, row)
			}
			if showTotal {
				if human {
					e.Printf("total %s\n", humanSize(total*1024))
				} else {
					e.Printf("total %d\n", total)
				}
			}
			widths := make([]int, 8)
			for _, r := range rows {
				for i, c := range r[:len(r)-1] {
					widths[i] = max(widths[i], len(c))
				}
			}
			for _, r := range rows {
				var b strings.Builder
				for i, c := range r[:len(r)-1] {
					if i == 1 || i == len(r)-3 { // numbers are right-aligned
						fmt.Fprintf(&b, "%*s ", widths[i], c)
					} else if i == len(r)-2 {
						b.WriteString(c + " ")
					} else {
						fmt.Fprintf(&b, "%-*s ", widths[i], c)
					}
				}
				b.WriteString(r[len(r)-1])
				e.Printf("%s\n", b.String())
			}
			return
		}
		if one || !e.IsTTY() {
			for _, ent := range ents {
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
			fmt.Fprintf(e.Stderr, "ls: cannot access '%s': %s\n", t, err)
			status = 2
			continue
		}
		if n.IsDir() && !dirOnly {
			dirs = append(dirs, lsEntry{name: t, node: n})
		} else {
			files = append(files, lsEntry{name: t, node: n})
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
			fmt.Fprintf(e.Stderr, "ls: cannot open directory '%s': %s\n", name, err)
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
			ents = append(ents, lsEntry{".", self}, lsEntry{"..", parent})
		}
		for _, c := range children {
			if strings.HasPrefix(c.Name, ".") && !all && !almost {
				continue
			}
			ents = append(ents, lsEntry{c.Name, c})
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
	node *vfs.Node
}

func lsColor(n *vfs.Node, name string) string {
	switch {
	case n.IsLink():
		return "\x1b[01;36m" + name + "\x1b[0m"
	case n.IsDir() && n.Mode&0o1000 != 0 && n.Mode&0o002 != 0:
		return "\x1b[30;42m" + name + "\x1b[0m"
	case n.IsDir():
		return "\x1b[01;34m" + name + "\x1b[0m"
	case n.Mode&0o4000 != 0:
		return "\x1b[37;41m" + name + "\x1b[0m"
	case n.Mode.Perm()&0o111 != 0:
		return "\x1b[01;32m" + name + "\x1b[0m"
	case strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tar") || strings.HasSuffix(name, ".zip") || strings.HasSuffix(name, ".tgz"):
		return "\x1b[01;31m" + name + "\x1b[0m"
	}
	return name
}

// modeString renders permissions the way ls -l does.
func modeString(n *vfs.Node) string {
	b := []byte("----------")
	switch {
	case n.IsDir():
		b[0] = 'd'
	case n.IsLink():
		b[0] = 'l'
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
	if now.Sub(t) > 180*24*time.Hour || t.Sub(now) > time.Hour {
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

// columns lays names out in vertical columns like GNU ls.
func columns(names []string, widths []int, termWidth int) string {
	if len(names) == 0 {
		return ""
	}
	for cols := len(names); cols >= 1; cols-- {
		rows := (len(names) + cols - 1) / cols
		cols := (len(names) + rows - 1) / rows
		colW := make([]int, cols)
		for i, w := range widths {
			c := i / rows
			colW[c] = max(colW[c], w+2)
		}
		total := 0
		for _, w := range colW {
			total += w
		}
		if total-2 > termWidth && cols > 1 {
			continue
		}
		var b strings.Builder
		for r := 0; r < rows; r++ {
			for c := 0; c < cols; c++ {
				i := c*rows + r
				if i >= len(names) {
					break
				}
				b.WriteString(names[i])
				last := c == cols-1 || (c+1)*rows+r >= len(names)
				if !last {
					b.WriteString(strings.Repeat(" ", colW[c]-widths[i]))
				}
			}
			b.WriteByte('\n')
		}
		return b.String()
	}
	return ""
}

package shell

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

func fsMode(v uint32) fs.FileMode { return fs.FileMode(v) }

// widther is implemented by terminals that know their width.
type widther interface{ Width() int }

func (e *Env) isTTY() bool { return e.Stdout == e.sh.term }

func (e *Env) termWidth() int {
	if w, ok := e.sh.term.(widther); ok && w.Width() > 0 {
		return w.Width()
	}
	return 80
}

func (e *Env) color() bool {
	return e.isTTY() && e.sh.cfg.Term != "" && e.sh.cfg.Term != "dumb"
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

func lsTime(t time.Time) string {
	if time.Since(t) > 180*24*time.Hour || time.Until(t) > time.Hour {
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

type lsEntry struct {
	name string
	node *vfs.Node
}

func cmdLs(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "color", "w", "sort", "time-style")
	long := o.has("l", "n", "g", "o")
	all := o.has("a", "all")
	almost := o.has("A", "almost-all")
	human := o.has("h", "human-readable")
	dirOnly := o.has("d", "directory")
	one := o.has("1")
	recursive := o.has("R", "recursive")
	classify := o.has("F", "classify")
	color := false
	if c, ok := o.val("color"); ok && c != "never" && c != "no" {
		color = c == "always" || e.color()
	}
	targets := o.pos
	if len(targets) == 0 {
		targets = []string{"."}
	}

	sortEntries := func(ents []lsEntry) {
		switch {
		case o.has("t"):
			sort.SliceStable(ents, func(i, j int) bool { return ents[i].node.ModTime.After(ents[j].node.ModTime) })
		case o.has("S"):
			sort.SliceStable(ents, func(i, j int) bool { return ents[i].node.Size() > ents[j].node.Size() })
		default:
			sort.SliceStable(ents, func(i, j int) bool {
				return strings.ToLower(strings.TrimLeft(ents[i].name, ".")) < strings.ToLower(strings.TrimLeft(ents[j].name, "."))
			})
		}
		if o.has("r") {
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
				if o.has("n") {
					owner, group = uidOf(owner), uidOf(group)
				}
				name := display(ent)
				if n.IsLink() {
					name += " -> " + n.Target
				}
				row := []string{modeString(n), strconv.Itoa(links), owner, group, size, lsTime(n.ModTime), name}
				if o.has("g") {
					row = append(row[:2], row[3:]...)
				} else if o.has("o") {
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
		if one || !e.isTTY() {
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
		e.Print(columns(names, plain, e.termWidth()))
	}

	var files []lsEntry
	var dirs []lsEntry
	status := 0
	for _, t := range targets {
		p := s.resolve(t)
		n, err := s.fs.Lstat(s.user, p)
		if err == nil && n.IsLink() && !long {
			if tn, err2 := s.fs.Stat(s.user, p); err2 == nil {
				n = tn
			}
		}
		if err == nil && n.IsLink() && long && strings.HasSuffix(t, "/") {
			n, err = s.fs.Stat(s.user, p)
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
		children, err := s.fs.ReadDir(s.user, p)
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
			self, _ := s.fs.Stat("root", p)
			parent, _ := s.fs.Stat("root", path.Dir(p))
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
		listDir(d.name, s.resolve(d.name), len(dirs)+len(files) > 1 || recursive)
	}
	return status
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

func uidOf(user string) string {
	switch user {
	case "root":
		return "0"
	case "www-data":
		return "33"
	case "ubuntu":
		return "1000"
	}
	return "1001"
}

func cmdCat(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	files := o.pos
	if len(files) == 0 {
		files = []string{"-"}
	}
	status := 0
	var out bytes.Buffer
	for _, f := range files {
		var data []byte
		if f == "-" {
			data = []byte(e.ReadStdin())
		} else {
			var err error
			data, err = s.fs.ReadFile(s.user, s.resolve(f))
			if err != nil {
				e.Errorf("%s: %s", f, err)
				status = 1
				continue
			}
		}
		out.Write(data)
	}
	if o.has("n") {
		lines := strings.SplitAfter(out.String(), "\n")
		for i, l := range lines {
			if l == "" {
				continue
			}
			e.Printf("%6d\t%s", i+1, l)
		}
		return status
	}
	_, _ = e.Stdout.Write(out.Bytes())
	return status
}

func cmdTouch(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "d", "t", "r", "date", "reference")
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "touch: missing file operand\nTry 'touch --help' for more information.")
		return 1
	}
	status := 0
	for _, f := range o.pos {
		if err := s.fs.Touch(s.user, s.resolve(f)); err != nil {
			e.Errorf("cannot touch '%s': %s", f, err)
			status = 1
		}
	}
	return status
}

func cmdMkdir(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "m", "mode")
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "mkdir: missing operand\nTry 'mkdir --help' for more information.")
		return 1
	}
	status := 0
	for _, d := range o.pos {
		if err := s.fs.Mkdir(s.user, s.resolve(d), o.has("p", "parents")); err != nil {
			e.Errorf("cannot create directory '%s': %s", d, err)
			status = 1
			continue
		}
		if m, ok := o.val("m", "mode"); ok {
			if v, err := strconv.ParseUint(m, 8, 32); err == nil {
				_ = s.fs.Chmod(s.user, s.resolve(d), fs.FileMode(v))
			}
		}
	}
	return status
}

func cmdRmdir(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	status := 0
	for _, d := range o.pos {
		if err := s.fs.Rmdir(s.user, s.resolve(d)); err != nil {
			e.Errorf("failed to remove '%s': %s", d, err)
			status = 1
		}
	}
	return status
}

func cmdRm(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	recursive := o.has("r", "R", "recursive")
	force := o.has("f", "force")
	if len(o.pos) == 0 {
		if force {
			return 0
		}
		fmt.Fprintln(e.Stderr, "rm: missing operand\nTry 'rm --help' for more information.")
		return 1
	}
	status := 0
	for _, f := range o.pos {
		p := s.resolve(f)
		if p == "/" && recursive && !o.has("no-preserve-root") {
			fmt.Fprintln(e.Stderr, "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe")
			status = 1
			continue
		}
		if base := path.Base(f); base == "." || base == ".." {
			fmt.Fprintf(e.Stderr, "rm: refusing to remove '.' or '..' directory: skipping '%s'\n", f)
			status = 1
			continue
		}
		if p == "/" {
			// --no-preserve-root: remove every top-level entry we can.
			ents, _ := s.fs.ReadDir(s.user, "/")
			for _, ent := range ents {
				if err := s.fs.Remove(s.user, "/"+ent.Name, true); err != nil && !force {
					e.Errorf("cannot remove '/%s': %s", ent.Name, err)
					status = 1
				}
			}
			continue
		}
		err := s.fs.Remove(s.user, p, recursive)
		if err == nil {
			continue
		}
		if force && errors.Is(err, vfs.ErrNotExist) {
			continue
		}
		e.Errorf("cannot remove '%s': %s", f, err)
		status = 1
	}
	return status
}

func cmdCp(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "t", "target-directory")
	srcs := o.pos
	dst, hasT := o.val("t", "target-directory")
	if !hasT {
		if len(srcs) < 2 {
			fmt.Fprintf(e.Stderr, "%s: missing destination file operand after '%s'\n", e.Args[0], strings.Join(srcs, " "))
			return 1
		}
		dst = srcs[len(srcs)-1]
		srcs = srcs[:len(srcs)-1]
	}
	status := 0
	for _, src := range srcs {
		var err error
		if e.Args[0] == "mv" {
			err = s.fs.Rename(s.user, s.resolve(src), s.resolve(dst))
		} else {
			if n, serr := s.fs.Stat(s.user, s.resolve(src)); serr == nil && n.IsDir() && !o.has("r", "R", "a", "recursive", "archive") {
				e.Errorf("-r not specified; omitting directory '%s'", src)
				status = 1
				continue
			}
			err = s.fs.Copy(s.user, s.resolve(src), s.resolve(dst), true)
		}
		if err != nil {
			if errors.Is(err, vfs.ErrNotExist) {
				e.Errorf("cannot stat '%s': %s", src, err)
			} else {
				verb := "cannot create regular file"
				if e.Args[0] == "mv" {
					verb = "cannot move '" + src + "' to"
				}
				e.Errorf("%s '%s': %s", verb, dst, err)
			}
			status = 1
		}
	}
	return status
}

func cmdLn(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "ln: missing file operand")
		return 1
	}
	target := o.pos[0]
	link := path.Base(target)
	if len(o.pos) > 1 {
		link = o.pos[1]
	}
	p := s.resolve(link)
	if n, err := s.fs.Stat(s.user, p); err == nil && n.IsDir() {
		p = path.Join(p, path.Base(target))
	}
	if o.has("f", "force") {
		_ = s.fs.Remove(s.user, p, false)
	}
	var err error
	if o.has("s", "symbolic") {
		err = s.fs.Symlink(s.user, target, p)
	} else {
		err = s.fs.Copy(s.user, s.resolve(target), p, false)
	}
	if err != nil {
		e.Errorf("failed to create link '%s': %s", link, err)
		return 1
	}
	return 0
}

// parseChmod applies an octal or symbolic mode spec to old.
func parseChmod(spec string, old fs.FileMode) (fs.FileMode, bool) {
	if v, err := strconv.ParseUint(spec, 8, 32); err == nil {
		return fs.FileMode(v) & 0o7777, true
	}
	mode := old & 0o7777
	for _, clause := range strings.Split(spec, ",") {
		i := 0
		var who fs.FileMode
		for i < len(clause) && strings.IndexByte("ugoa", clause[i]) >= 0 {
			switch clause[i] {
			case 'u':
				who |= 0o4700
			case 'g':
				who |= 0o2070
			case 'o':
				who |= 0o1007
			case 'a':
				who |= 0o7777
			}
			i++
		}
		if who == 0 {
			who = 0o7777
		}
		if i >= len(clause) || strings.IndexByte("+-=", clause[i]) < 0 {
			return 0, false
		}
		op := clause[i]
		i++
		var bits fs.FileMode
		for ; i < len(clause); i++ {
			switch clause[i] {
			case 'r':
				bits |= 0o444
			case 'w':
				bits |= 0o222
			case 'x', 'X':
				bits |= 0o111
			case 's':
				bits |= 0o6000
			case 't':
				bits |= 0o1000
			default:
				return 0, false
			}
		}
		bits &= who
		switch op {
		case '+':
			mode |= bits
		case '-':
			mode &^= bits
		case '=':
			mode = (mode &^ (who & 0o777)) | bits
		}
	}
	return mode, true
}

func cmdChmod(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	recursive := false
	var rest []string
	for _, a := range args {
		switch {
		case a == "-R" || a == "--recursive":
			recursive = true
		case a == "-f" || a == "-v" || a == "-c":
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) < 2 {
		fmt.Fprintln(e.Stderr, "chmod: missing operand\nTry 'chmod --help' for more information.")
		return 1
	}
	spec := rest[0]
	status := 0
	var apply func(p, name string)
	apply = func(p, name string) {
		n, err := s.fs.Stat(s.user, p)
		if err != nil {
			e.Errorf("cannot access '%s': %s", name, err)
			status = 1
			return
		}
		mode, ok := parseChmod(spec, n.Mode)
		if !ok {
			e.Errorf("invalid mode: '%s'", spec)
			status = 1
			return
		}
		if err := s.fs.Chmod(s.user, p, mode); err != nil {
			e.Errorf("changing permissions of '%s': %s", name, err)
			status = 1
		}
		if recursive && n.IsDir() {
			children, _ := s.fs.ReadDir(s.user, p)
			for _, c := range children {
				apply(path.Join(p, c.Name), path.Join(name, c.Name))
			}
		}
	}
	for _, f := range rest[1:] {
		apply(s.resolve(f), f)
	}
	return status
}

func cmdChown(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	if len(o.pos) < 2 {
		fmt.Fprintf(e.Stderr, "%s: missing operand\n", e.Args[0])
		return 1
	}
	owner, group, _ := strings.Cut(o.pos[0], ":")
	if e.Args[0] == "chgrp" {
		owner, group = "", o.pos[0]
	}
	status := 0
	for _, f := range o.pos[1:] {
		if err := s.fs.Chown(s.user, s.resolve(f), owner, group); err != nil {
			e.Errorf("changing ownership of '%s': %s", f, err)
			status = 1
		}
	}
	return status
}

func cmdChattr(e *Env) int {
	if e.sh.uid != 0 {
		for _, a := range e.Args[1:] {
			if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") && !strings.HasPrefix(a, "=") {
				e.Errorf("Operation not permitted while setting flags on %s", a)
				return 1
			}
		}
	}
	return 0
}

func cmdStat(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "c", "format")
	status := 0
	for _, f := range o.pos {
		n, err := s.fs.Lstat(s.user, s.resolve(f))
		if err != nil {
			e.Errorf("cannot statx '%s': %s", f, err)
			status = 1
			continue
		}
		if fm, ok := o.val("c", "format"); ok {
			r := strings.NewReplacer("%n", f, "%s", strconv.FormatInt(n.Size(), 10), "%a", strconv.FormatUint(uint64(n.Mode.Perm()), 8),
				"%A", modeString(n), "%U", n.Owner, "%G", n.Group, "%u", uidOf(n.Owner), "%Y", strconv.FormatInt(n.ModTime.Unix(), 10))
			e.Printf("%s\n", r.Replace(fm))
			continue
		}
		kind := "regular file"
		switch {
		case n.IsDir():
			kind = "directory"
		case n.IsLink():
			kind = "symbolic link"
		case n.Size() == 0:
			kind = "regular empty file"
		}
		name := f
		if n.IsLink() {
			name = fmt.Sprintf("%s -> %s", f, n.Target)
		}
		ts := n.ModTime.Format("2006-01-02 15:04:05.000000000 -0700")
		e.Printf("  File: %s\n  Size: %-10d\tBlocks: %-10d IO Block: 4096   %s\nDevice: 801h/2049d\tInode: %-11d Links: 1\nAccess: (%04o/%s)  Uid: (%5s/%8s)   Gid: (%5s/%8s)\nAccess: %s\nModify: %s\nChange: %s\n Birth: %s\n",
			name, n.Size(), (n.Size()+511)/512, kind, 262144+len(f)*7919%100000, n.Mode.Perm(), modeString(n),
			uidOf(n.Owner), n.Owner, uidOf(n.Group), n.Group, ts, ts, ts, ts)
	}
	return status
}

func fileType(n *vfs.Node, data []byte) string {
	switch {
	case n.IsDir():
		return "directory"
	case n.IsLink():
		return "symbolic link to " + n.Target
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3f1e0a4f2b8c6e2d7a9b1c0d5e4f3a2b1c0d9e8f, for GNU/Linux 3.2.0, stripped"
	case bytes.HasPrefix(data, []byte("\x1f\x8b")):
		return "gzip compressed data, from Unix"
	case len(data) == 0 && n.FakeSize == 0:
		return "empty"
	case bytes.HasPrefix(data, []byte("#!/bin/bash")) || bytes.HasPrefix(data, []byte("#!/usr/bin/env bash")):
		return "Bourne-Again shell script, ASCII text executable"
	case bytes.HasPrefix(data, []byte("#!/bin/sh")):
		return "POSIX shell script, ASCII text executable"
	case bytes.HasPrefix(data, []byte("#!/usr/bin/python")) || bytes.HasPrefix(data, []byte("#!/usr/bin/env python")):
		return "Python script, ASCII text executable"
	case bytes.HasPrefix(data, []byte("<?php")):
		return "PHP script, ASCII text"
	case !isText(data):
		return "data"
	}
	return "ASCII text"
}

func cmdFile(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "Usage: file [-bcdEhikLlNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n            [--mime-type] [-e <testname>] [-F <separator>]  [-f <namefile>]\n            [-m <magicfiles>] [-P <parameter=value>] [--exclude-quiet]\n            <file> ...")
		return 1
	}
	for _, f := range o.pos {
		p := s.resolve(f)
		n, err := s.fs.Lstat(s.user, p)
		if err != nil {
			e.Printf("%s: cannot open `%s' (%s)\n", f, f, err)
			continue
		}
		data, _ := s.fs.ReadFile(s.user, p)
		if o.has("b") {
			e.Printf("%s\n", fileType(n, data))
		} else {
			e.Printf("%s: %s\n", f, fileType(n, data))
		}
	}
	return 0
}

func cmdFind(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	var roots []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") && args[0] != "(" && args[0] != "!" {
		roots = append(roots, args[0])
		args = args[1:]
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var namePat, typ, iname string
	maxDepth := -1
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "-name":
			namePat = next()
		case "-iname":
			iname = strings.ToLower(next())
		case "-type":
			typ = next()
		case "-maxdepth":
			maxDepth, _ = strconv.Atoi(next())
		case "-perm", "-user", "-group", "-size", "-mtime", "-newer", "-path", "-mindepth":
			next()
		case "-exec", "-execdir", "-ok":
			for i < len(args) && args[i] != ";" && args[i] != "+" {
				i++
			}
		}
	}
	status := 0
	var walk func(p, shown string, depth int)
	walk = func(p, shown string, depth int) {
		if e.Ctx.Err() != nil {
			return
		}
		n, err := s.fs.Lstat(s.user, p)
		if err != nil {
			fmt.Fprintf(e.Stderr, "find: '%s': %s\n", shown, err)
			status = 1
			return
		}
		match := true
		name := path.Base(p)
		if namePat != "" {
			match, _ = path.Match(namePat, name)
		}
		if match && iname != "" {
			match, _ = path.Match(iname, strings.ToLower(name))
		}
		if match && typ != "" {
			switch typ {
			case "f":
				match = !n.IsDir() && !n.IsLink()
			case "d":
				match = n.IsDir()
			case "l":
				match = n.IsLink()
			}
		}
		if match {
			e.Printf("%s\n", shown)
		}
		if !n.IsDir() || (maxDepth >= 0 && depth >= maxDepth) {
			return
		}
		children, err := s.fs.ReadDir(s.user, p)
		if err != nil {
			fmt.Fprintf(e.Stderr, "find: '%s': %s\n", shown, err)
			status = 1
			return
		}
		for _, c := range children {
			child := shown + "/" + c.Name
			if shown == "/" {
				child = "/" + c.Name
			}
			walk(path.Join(p, c.Name), child, depth+1)
		}
	}
	for _, r := range roots {
		walk(s.resolve(r), strings.TrimSuffix(r, "/")+map[bool]string{true: "/", false: ""}[r == "/"], 0)
	}
	return status
}

func treeSize(n *vfs.Node) int64 {
	total := (n.Size() + 4095) / 4096 * 4096
	for _, c := range n.Children {
		total += treeSize(c)
	}
	return total
}

func cmdDu(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "d", "max-depth")
	targets := o.pos
	if len(targets) == 0 {
		targets = []string{"."}
	}
	format := func(n int64) string {
		if o.has("h", "human-readable") {
			return humanSize(n)
		}
		return strconv.FormatInt(n/1024, 10)
	}
	status := 0
	for _, t := range targets {
		n, err := s.fs.Stat(s.user, s.resolve(t))
		if err != nil {
			e.Errorf("cannot access '%s': %s", t, err)
			status = 1
			continue
		}
		if !o.has("s", "summarize") && n.IsDir() {
			for _, c := range n.Children {
				if c.IsDir() {
					e.Printf("%s\t%s\n", format(treeSize(c)), path.Join(t, c.Name))
				}
			}
		}
		e.Printf("%s\t%s\n", format(treeSize(n)), t)
	}
	return status
}

func cmdReadlink(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	status := 0
	for _, f := range o.pos {
		p := s.resolve(f)
		if o.has("f", "e", "m", "canonicalize") || e.Args[0] == "realpath" {
			rp, err := s.fs.Realpath(s.user, p)
			if err != nil {
				if e.Args[0] == "realpath" {
					e.Errorf("%s: %s", f, err)
				}
				status = 1
				continue
			}
			e.Printf("%s\n", rp)
			continue
		}
		n, err := s.fs.Lstat(s.user, p)
		if err != nil || !n.IsLink() {
			status = 1
			continue
		}
		e.Printf("%s\n", n.Target)
	}
	return status
}

func cmdBasename(e *Env) int {
	if len(e.Args) < 2 {
		fmt.Fprintln(e.Stderr, "basename: missing operand")
		return 1
	}
	b := path.Base(e.Args[1])
	if len(e.Args) > 2 {
		b = strings.TrimSuffix(b, e.Args[2])
	}
	e.Printf("%s\n", b)
	return 0
}

func cmdDirname(e *Env) int {
	if len(e.Args) < 2 {
		fmt.Fprintln(e.Stderr, "dirname: missing operand")
		return 1
	}
	for _, a := range e.Args[1:] {
		e.Printf("%s\n", path.Dir(a))
	}
	return 0
}

func cmdWhich(e *Env) int {
	o := getopt(e.Args[1:])
	status := 0
	for _, n := range o.pos {
		if p, ok := e.sh.lookPath(n); ok {
			e.Printf("%s\n", p)
		} else {
			status = 1
		}
	}
	return status
}

func cmdWhereis(e *Env) int {
	for _, n := range e.Args[1:] {
		out := n + ":"
		if p, ok := e.sh.lookPath(n); ok {
			out += " " + p
			if !strings.HasPrefix(p, "/usr/") {
				out += " /usr" + p
			}
			out += " /usr/share/man/man1/" + n + ".1.gz"
		}
		e.Printf("%s\n", out)
	}
	return 0
}

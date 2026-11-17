package commands

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
	"github.com/antonmedv/ssham/internal/vfs"
)

func init() {
	register(
		shell.Command{Name: "cat", Aliases: []string{"less", "more"}, Run: cmdCat},
		shell.Command{Name: "touch", Run: cmdTouch},
		shell.Command{Name: "mkdir", Run: cmdMkdir},
		shell.Command{Name: "rmdir", Run: cmdRmdir},
		shell.Command{Name: "rm", Aliases: []string{"shred"}, Run: cmdRm},
		shell.Command{Name: "cp", Aliases: []string{"mv"}, Run: cmdCp},
		shell.Command{Name: "ln", Run: cmdLn},
		shell.Command{Name: "chmod", Run: cmdChmod},
		shell.Command{Name: "chown", Aliases: []string{"chgrp"}, Run: cmdChown},
		shell.Command{Name: "chattr", Run: cmdChattr},
		shell.Command{Name: "stat", Run: cmdStat},
		shell.Command{Name: "file", Run: cmdFile},
		shell.Command{Name: "du", Run: cmdDu},
		shell.Command{Name: "readlink", Aliases: []string{"realpath"}, Run: cmdReadlink},
		shell.Command{Name: "basename", Run: cmdBasename},
		shell.Command{Name: "dirname", Run: cmdDirname},
		shell.Command{Name: "which", Run: cmdWhich},
		shell.Command{Name: "whereis", Run: cmdWhereis},
		shell.Command{Name: "tar", Aliases: []string{"gzip", "gunzip", "unzip"}, Run: cmdArchive},
		shell.Command{Name: "dd", Run: cmdDd},
	)
}

func cmdCat(e *shell.Env) int {
	o := e.Flags()
	files := o.Args
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
			data, err = e.FS.ReadFile(f)
			if err != nil {
				e.Errorf("%s: %s", f, err)
				status = 1
				continue
			}
		}
		out.Write(data)
	}
	if o.Has("n") {
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

func cmdTouch(e *shell.Env) int {
	o := e.Flags("d", "t", "r", "date", "reference")
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "touch: missing file operand\nTry 'touch --help' for more information.")
		return 1
	}
	status := 0
	for _, f := range o.Args {
		if err := e.FS.Touch(f); err != nil {
			e.Errorf("cannot touch '%s': %s", f, err)
			status = 1
		}
	}
	return status
}

func cmdMkdir(e *shell.Env) int {
	o := e.Flags("m", "mode")
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "mkdir: missing operand\nTry 'mkdir --help' for more information.")
		return 1
	}
	status := 0
	for _, d := range o.Args {
		if err := e.FS.Mkdir(d, o.Has("p", "parents")); err != nil {
			e.Errorf("cannot create directory '%s': %s", d, err)
			status = 1
			continue
		}
		if m, ok := o.Value("m", "mode"); ok {
			if v, err := strconv.ParseUint(m, 8, 32); err == nil {
				_ = e.FS.Chmod(d, fs.FileMode(v))
			}
		}
	}
	return status
}

func cmdRmdir(e *shell.Env) int {
	o := e.Flags()
	status := 0
	for _, d := range o.Args {
		if err := e.FS.Rmdir(d); err != nil {
			e.Errorf("failed to remove '%s': %s", d, err)
			status = 1
		}
	}
	return status
}

func cmdRm(e *shell.Env) int {
	o := e.Flags()
	recursive := o.Has("r", "R", "recursive")
	force := o.Has("f", "force")
	if len(o.Args) == 0 {
		if force {
			return 0
		}
		fmt.Fprintln(e.Stderr, "rm: missing operand\nTry 'rm --help' for more information.")
		return 1
	}
	status := 0
	for _, f := range o.Args {
		p := e.FS.Abs(f)
		if p == "/" && recursive && !o.Has("no-preserve-root") {
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
			ents, _ := e.FS.ReadDir("/")
			for _, ent := range ents {
				if err := e.FS.Remove("/"+ent.Name, true); err != nil && !force {
					e.Errorf("cannot remove '/%s': %s", ent.Name, err)
					status = 1
				}
			}
			continue
		}
		err := e.FS.Remove(p, recursive)
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

func cmdCp(e *shell.Env) int {
	o := e.Flags("t", "target-directory")
	srcs := o.Args
	dst, hasT := o.Value("t", "target-directory")
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
			err = e.FS.Rename(src, e.FS.Abs(dst))
		} else {
			if n, serr := e.FS.Stat(src); serr == nil && n.IsDir() && !o.Has("r", "R", "a", "recursive", "archive") {
				e.Errorf("-r not specified; omitting directory '%s'", src)
				status = 1
				continue
			} else if serr == nil && !n.IsDir() && !e.FS.Can(n, vfs.Read) {
				e.Errorf("cannot open '%s' for reading: Permission denied", src)
				status = 1
				continue
			}
			err = e.FS.Copy(src, e.FS.Abs(dst), true)
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

func cmdLn(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "ln: missing file operand")
		return 1
	}
	target := o.Args[0]
	link := path.Base(target)
	if len(o.Args) > 1 {
		link = o.Args[1]
	}
	p := e.FS.Abs(link)
	if n, err := e.FS.Stat(p); err == nil && n.IsDir() {
		p = path.Join(p, path.Base(target))
	}
	if o.Has("f", "force") {
		_ = e.FS.Remove(p, false)
	}
	var err error
	if o.Has("s", "symbolic") {
		err = e.FS.Symlink(target, p)
	} else {
		err = e.FS.Copy(target, p, false)
	}
	if err != nil {
		e.Errorf("failed to create link '%s': %s", link, err)
		return 1
	}
	return 0
}

func cmdChmod(e *shell.Env) int {
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
		n, err := e.FS.Stat(p)
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
		if err := e.FS.Chmod(p, mode); err != nil {
			e.Errorf("changing permissions of '%s': %s", name, err)
			status = 1
		}
		if recursive && n.IsDir() {
			children, _ := e.FS.ReadDir(p)
			for _, c := range children {
				apply(path.Join(p, c.Name), path.Join(name, c.Name))
			}
		}
	}
	for _, f := range rest[1:] {
		apply(e.FS.Abs(f), f)
	}
	return status
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

func cmdChown(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) < 2 {
		fmt.Fprintf(e.Stderr, "%s: missing operand\n", e.Args[0])
		return 1
	}
	owner, group, _ := strings.Cut(o.Args[0], ":")
	if e.Args[0] == "chgrp" {
		owner, group = "", o.Args[0]
	}
	status := 0
	for _, f := range o.Args[1:] {
		if err := e.FS.Chown(f, owner, group); err != nil {
			e.Errorf("changing ownership of '%s': %s", f, err)
			status = 1
		}
	}
	return status
}

func cmdChattr(e *shell.Env) int {
	if !e.User().IsRoot() {
		for _, a := range e.Args[1:] {
			if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") && !strings.HasPrefix(a, "=") {
				e.Errorf("Operation not permitted while setting flags on %s", a)
				return 1
			}
		}
	}
	return 0
}

func cmdStat(e *shell.Env) int {
	o := e.Flags("c", "format")
	status := 0
	for _, f := range o.Args {
		n, err := e.FS.Lstat(f)
		if err != nil {
			e.Errorf("cannot statx '%s': %s", f, err)
			status = 1
			continue
		}
		if fm, ok := o.Value("c", "format"); ok {
			r := strings.NewReplacer("%n", f, "%s", strconv.FormatInt(n.Size(), 10), "%a", strconv.FormatUint(uint64(n.Mode&0o7777), 8),
				"%A", modeString(n), "%U", n.Owner, "%G", n.Group, "%u", uidOf(e, n.Owner), "%Y", strconv.FormatInt(n.ModTime.Unix(), 10))
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
			uidOf(e, n.Owner), n.Owner, gidOf(e, n.Group), n.Group, ts, ts, ts, ts)
	}
	return status
}

func cmdFile(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "Usage: file [-bcdEhikLlNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n            [--mime-type] [-e <testname>] [-F <separator>]  [-f <namefile>]\n            [-m <magicfiles>] [-P <parameter=value>] [--exclude-quiet]\n            <file> ...")
		return 1
	}
	for _, f := range o.Args {
		p := e.FS.Abs(f)
		n, err := e.FS.Lstat(p)
		if err != nil {
			e.Printf("%s: cannot open `%s' (%s)\n", f, f, err)
			continue
		}
		data, _ := e.FS.ReadFile(p)
		if o.Has("b") {
			e.Printf("%s\n", fileType(n, data))
		} else {
			e.Printf("%s: %s\n", f, fileType(n, data))
		}
	}
	return 0
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

func cmdDu(e *shell.Env) int {
	o := e.Flags("d", "max-depth")
	targets := o.Args
	if len(targets) == 0 {
		targets = []string{"."}
	}
	format := func(n int64) string {
		if o.Has("h", "human-readable") {
			return humanSize(n)
		}
		return strconv.FormatInt(n/1024, 10)
	}
	status := 0
	for _, t := range targets {
		n, err := e.FS.Stat(t)
		if err != nil {
			e.Errorf("cannot access '%s': %s", t, err)
			status = 1
			continue
		}
		if !o.Has("s", "summarize") && n.IsDir() {
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

func treeSize(n *vfs.Node) int64 {
	total := (n.Size() + 4095) / 4096 * 4096
	for _, c := range n.Children {
		total += treeSize(c)
	}
	return total
}

func cmdReadlink(e *shell.Env) int {
	o := e.Flags()
	status := 0
	for _, f := range o.Args {
		p := e.FS.Abs(f)
		if o.Has("f", "e", "m", "canonicalize") || e.Args[0] == "realpath" {
			rp, err := e.FS.Realpath(p)
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
		n, err := e.FS.Lstat(p)
		if err != nil || !n.IsLink() {
			status = 1
			continue
		}
		e.Printf("%s\n", n.Target)
	}
	return status
}

func cmdBasename(e *shell.Env) int {
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

func cmdDirname(e *shell.Env) int {
	if len(e.Args) < 2 {
		fmt.Fprintln(e.Stderr, "dirname: missing operand")
		return 1
	}
	for _, a := range e.Args[1:] {
		e.Printf("%s\n", path.Dir(a))
	}
	return 0
}

func cmdWhich(e *shell.Env) int {
	o := e.Flags()
	status := 0
	for _, n := range o.Args {
		if p, ok := e.LookPath(n); ok {
			e.Printf("%s\n", p)
		} else {
			status = 1
		}
	}
	return status
}

func cmdWhereis(e *shell.Env) int {
	for _, n := range e.Args[1:] {
		out := n + ":"
		if p, ok := e.LookPath(n); ok {
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

func cmdArchive(e *shell.Env) int {
	// tar, gzip, unzip and friends: pretend to work on files that exist.
	args := e.Args[1:]
	if e.Args[0] == "tar" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append([]string{"-" + args[0]}, args[1:]...) // tar xzf: old-style flags
	}
	o := shell.ParseFlags(args, "f", "C")
	if f, ok := o.Value("f"); ok {
		if _, err := e.FS.Stat(f); err != nil && !o.Has("c") {
			fmt.Fprintf(e.Stderr, "%s: %s: Cannot open: %s\n%s: Error is not recoverable: exiting now\n", e.Args[0], f, err, e.Args[0])
			return 2
		}
		if o.Has("x") {
			e.Log(audit.ArchiveExtract, "path", e.FS.Abs(f))
		}
		return 0
	}
	for _, f := range o.Args {
		if _, err := e.FS.Stat(f); err != nil {
			fmt.Fprintf(e.Stderr, "%s: %s: %s\n", e.Args[0], f, err)
			return 1
		}
	}
	return 0
}

func cmdDd(e *shell.Env) int {
	var count, bs int64 = 0, 512
	for _, a := range e.Args[1:] {
		k, v, _ := strings.Cut(a, "=")
		n, _ := strconv.ParseInt(strings.TrimRight(v, "KMGkmgB"), 10, 64)
		switch strings.ToUpper(strings.TrimLeft(v, "0123456789")) {
		case "K":
			n *= 1024
		case "M":
			n *= 1 << 20
		case "G":
			n *= 1 << 30
		}
		switch k {
		case "count":
			count = n
		case "bs":
			bs = n
		}
	}
	total := count * bs
	fmt.Fprintf(e.Stderr, "%d+0 records in\n%d+0 records out\n%d bytes (%s) copied, 0.0123 s, %s/s\n", count, count, total, humanSize(total), humanSize(total*80))
	return 0
}

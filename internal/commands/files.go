package commands

import (
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
		shell.Command{Name: "cat", Usage: "[-nb] [FILE]...", Run: cmdCat},
		shell.Command{Name: "more", Usage: "[FILE]...", Run: cmdCat},
		shell.Command{Name: "touch", Usage: "[-c] [-d DATE] [-t DATE] [-r FILE] FILE...", Run: cmdTouch},
		shell.Command{Name: "mkdir", Usage: "[-m MODE] [-p] DIRECTORY...", Run: cmdMkdir},
		shell.Command{Name: "rmdir", Usage: "[-p] DIRECTORY...", Run: cmdRmdir},
		shell.Command{Name: "rm", Usage: "[-irf] FILE...", Run: cmdRm},
		shell.Command{Name: "cp", Usage: "[OPTIONS] SOURCE... DEST", Run: cmdCp},
		shell.Command{Name: "mv", Usage: "[-fin] SOURCE DEST\nor: mv [-fin] SOURCE... DIRECTORY", Run: cmdCp},
		shell.Command{Name: "ln", Usage: "[OPTIONS] TARGET... LINK|DIR", Run: cmdLn},
		shell.Command{Name: "chmod", Usage: "[-Rcvf] MODE[,MODE]... FILE...", Run: cmdChmod},
		shell.Command{Name: "chown", Usage: "[-RhLHPcvf]... USER[:[GRP]] FILE...", Run: cmdChown},
		shell.Command{Name: "basename", Dir: "/usr/bin", Usage: "FILE [SUFFIX]", Run: cmdBasename},
		shell.Command{Name: "dirname", Dir: "/usr/bin", Usage: "FILENAME", Run: cmdDirname},
		shell.Command{Name: "which", Dir: "/usr/bin", Usage: "[COMMAND]...", Run: cmdWhich},
		shell.Command{Name: "tar", Usage: "-[cxtzhvO] [-f TARFILE] [-C DIR] [FILE]...", Run: cmdArchive},
		shell.Command{Name: "gzip", Usage: "[-cfkdt] [FILE]...", Run: cmdArchive},
		shell.Command{Name: "gunzip", Usage: "[-cfkt] [FILE]...", Run: cmdArchive},
		shell.Command{Name: "dd", Usage: "[if=FILE] [of=FILE] [bs=N] [count=N] [skip=N] [seek=N]", Run: cmdDd},
		shell.Command{Name: "sync", Usage: "", Run: func(*shell.Env) int { return 0 }},
	)
}

func cmdCat(e *shell.Env) int {
	o := e.Flags()
	data, status := e.ReadFiles(o.Args)
	if o.Has("n") {
		for i, l := range splitLines(data) {
			e.Printf("%6d\t%s\n", i+1, l)
		}
		return status
	}
	e.Print(data)
	return status
}

func cmdTouch(e *shell.Env) int {
	o := e.Flags("d", "t", "r")
	if len(o.Args) == 0 {
		return e.Usage()
	}
	status := 0
	for _, f := range o.Args {
		if o.Has("c") {
			if _, err := e.FS.Stat(f); err != nil {
				continue
			}
		}
		if err := e.FS.Touch(f); err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
		}
	}
	return status
}

func cmdMkdir(e *shell.Env) int {
	o := e.Flags("m")
	if len(o.Args) == 0 {
		return e.Usage()
	}
	status := 0
	for _, d := range o.Args {
		if err := e.FS.Mkdir(d, o.Has("p")); err != nil {
			e.Errorf("can't create directory '%s': %s", d, err)
			status = 1
			continue
		}
		if m, ok := o.Value("m"); ok {
			if v, err := strconv.ParseUint(m, 8, 32); err == nil {
				_ = e.FS.Chmod(d, fs.FileMode(v))
			}
		}
	}
	return status
}

func cmdRmdir(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		return e.Usage()
	}
	status := 0
	for _, d := range o.Args {
		if err := e.FS.Rmdir(d); err != nil {
			e.Errorf("'%s': %s", d, err)
			status = 1
		}
	}
	return status
}

// cmdRm has no --preserve-root, like BusyBox. rm -r walks the tree the
// way the real one does: it empties writable mounts and fails on the
// read-only root and on the mount points themselves.
func cmdRm(e *shell.Env) int {
	o := e.Flags()
	recursive, force := o.Has("r", "R"), o.Has("f")
	if len(o.Args) == 0 {
		if force {
			return 0
		}
		return e.Usage()
	}
	status := 0
	fail := func(p string, err error) {
		e.Errorf("can't remove '%s': %s", p, err)
		status = 1
	}
	var removeAll func(p string)
	removeAll = func(p string) {
		n, err := e.FS.Lstat(p)
		if err != nil {
			if !force {
				fail(p, err)
			}
			return
		}
		if n.IsDir() {
			children, err := e.FS.ReadDir(p)
			if err != nil {
				fail(p, err)
				return
			}
			for _, c := range children {
				removeAll(path.Join(p, c.Name))
			}
		}
		if err := e.FS.Remove(p, true); err != nil && !(force && errors.Is(err, vfs.ErrNotExist)) {
			fail(p, err)
		}
	}
	for _, f := range o.Args {
		if base := path.Base(f); base == "." || base == ".." {
			e.Errorf("can't remove '.' or '..'")
			status = 1
			continue
		}
		n, err := e.FS.Lstat(f)
		switch {
		case err != nil:
			if !force || !errors.Is(err, vfs.ErrNotExist) {
				fail(f, err)
			}
		case n.IsDir() && !recursive:
			e.Errorf("'%s' is a directory", f)
			status = 1
		case n.IsDir() && e.FS.Abs(f) == "/":
			ents, _ := e.FS.ReadDir("/")
			for _, ent := range ents {
				removeAll("/" + ent.Name)
			}
		case n.IsDir():
			removeAll(f)
		default:
			if err := e.FS.Remove(f, false); err != nil {
				fail(f, err)
			}
		}
	}
	return status
}

// cmdCp implements cp and mv.
func cmdCp(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) < 2 {
		return e.Usage()
	}
	srcs, dst := o.Args[:len(o.Args)-1], o.Args[len(o.Args)-1]
	if n, err := e.FS.Stat(dst); len(srcs) > 1 && (err != nil || !n.IsDir()) {
		e.Errorf("'%s' is not a directory", dst)
		return 1
	}
	move := path.Base(e.Args[0]) == "mv"
	status := 0
	for _, src := range srcs {
		n, err := e.FS.Lstat(src)
		if err != nil {
			e.Errorf("can't stat '%s': %s", src, err)
			status = 1
			continue
		}
		if move {
			if err := e.FS.Rename(src, dst); err != nil {
				e.Errorf("can't rename '%s': %s", src, err)
				status = 1
			}
			continue
		}
		if n.IsDir() && !o.Has("r", "R", "a") {
			e.Errorf("omitting directory '%s'", src)
			status = 1
			continue
		}
		if !n.IsDir() && !e.FS.Can(n, vfs.Read) {
			e.Errorf("can't open '%s': %s", src, vfs.ErrPermission)
			status = 1
			continue
		}
		if err := e.FS.Copy(src, dst, true); err != nil {
			e.Errorf("can't create '%s': %s", dst, err)
			status = 1
		}
	}
	return status
}

func cmdLn(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		return e.Usage()
	}
	target := o.Args[0]
	link := path.Base(target)
	if len(o.Args) > 1 {
		link = o.Args[1]
	}
	if n, err := e.FS.Stat(link); err == nil && n.IsDir() {
		link = path.Join(link, path.Base(target))
	}
	if o.Has("f") {
		_ = e.FS.Remove(link, false)
	}
	var err error
	if o.Has("s") {
		err = e.FS.Symlink(target, link)
	} else {
		err = e.FS.Copy(target, link, false)
	}
	if err != nil {
		e.Errorf("%s: %s", link, err)
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

func cmdChmod(e *shell.Env) int {
	recursive := false
	var rest []string
	for _, a := range e.Args[1:] {
		switch a {
		case "-R":
			recursive = true
		case "-f", "-v", "-c":
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) < 2 {
		return e.Usage()
	}
	spec := rest[0]
	if _, ok := parseChmod(spec, 0); !ok {
		e.Errorf("invalid mode '%s'", spec)
		return 1
	}
	status := 0
	var apply func(name string)
	apply = func(name string) {
		n, err := e.FS.Stat(name)
		if err != nil {
			e.Errorf("%s: %s", name, err)
			status = 1
			return
		}
		mode, _ := parseChmod(spec, n.Mode)
		if err := e.FS.Chmod(name, mode); err != nil {
			e.Errorf("%s: %s", name, err)
			status = 1
		}
		if recursive && n.IsDir() {
			children, _ := e.FS.ReadDir(name)
			for _, c := range children {
				apply(path.Join(name, c.Name))
			}
		}
	}
	for _, f := range rest[1:] {
		apply(f)
	}
	return status
}

func cmdChown(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) < 2 {
		return e.Usage()
	}
	owner, group, _ := strings.Cut(o.Args[0], ":")
	if _, ok := e.LookupUser(owner); owner != "" && !ok {
		e.Errorf("unknown user %s", owner)
		return 1
	}
	if group != "" && e.GroupID(group) < 0 {
		e.Errorf("unknown group %s", group)
		return 1
	}
	status := 0
	for _, f := range o.Args[1:] {
		if err := e.FS.Chown(f, owner, group); err != nil {
			e.Errorf("%s: %s", f, err)
			status = 1
		}
	}
	return status
}

func cmdBasename(e *shell.Env) int {
	if len(e.Args) < 2 {
		return e.Usage()
	}
	b := path.Base(e.Args[1])
	if len(e.Args) > 2 && b != e.Args[2] {
		b = strings.TrimSuffix(b, e.Args[2])
	}
	e.Printf("%s\n", b)
	return 0
}

func cmdDirname(e *shell.Env) int {
	if len(e.Args) != 2 {
		return e.Usage()
	}
	e.Printf("%s\n", path.Dir(e.Args[1]))
	return 0
}

func cmdWhich(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		return e.Usage()
	}
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

// cmdArchive implements tar, gzip and gunzip: they check their files and
// pretend to work.
func cmdArchive(e *shell.Env) int {
	name := path.Base(e.Args[0])
	args := e.Args[1:]
	if name == "tar" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append([]string{"-" + args[0]}, args[1:]...) // tar xzf: old-style flags
	}
	o := shell.ParseFlags(args, "f", "C")
	if name == "tar" {
		f, ok := o.Value("f")
		if !ok && !o.Has("c", "x", "t") {
			return e.Usage()
		}
		if ok && !o.Has("c") {
			if _, err := e.FS.Stat(f); err != nil {
				e.Errorf("can't open '%s': %s", f, err)
				return 1
			}
			if o.Has("x") {
				e.Log(audit.ArchiveExtract, "path", e.FS.Abs(f))
			}
		}
		return 0
	}
	for _, f := range o.Args {
		if _, err := e.FS.Stat(f); err != nil {
			e.Errorf("can't open '%s': %s", f, err)
			return 1
		}
	}
	return 0
}

// cmdDd copies data for real, within the in-memory filesystem: bots read
// the first bytes of a binary (dd bs=52 count=1 if=/bin/echo) to learn the
// CPU architecture.
func cmdDd(e *shell.Env) int {
	in, out := "", ""
	var bs, count, skip int64 = 512, -1, 0
	for _, a := range e.Args[1:] {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return e.Usage()
		}
		switch k {
		case "if":
			in = v
		case "of":
			out = v
		case "bs", "count", "skip":
			n, err := parseSize(v)
			if err != nil {
				e.Errorf("invalid number '%s'", v)
				return 1
			}
			switch k {
			case "bs":
				bs = n
			case "count":
				count = n
			case "skip":
				skip = n
			}
		}
	}
	var data []byte
	switch in {
	case "":
		data = []byte(e.ReadStdin())
	case "/dev/zero":
		data = make([]byte, min(max(count, 1)*bs, 4<<20))
	case "/dev/urandom", "/dev/random":
		data = make([]byte, min(max(count, 1)*bs, 4<<20))
		for i := range data {
			data[i] = byte(e.Rand().Uint32())
		}
	default:
		var err error
		if data, err = e.FS.ReadFile(in); err != nil {
			e.Errorf("can't open '%s': %s", in, err)
			return 1
		}
	}
	data = data[min(int64(len(data)), skip*bs):]
	if count >= 0 {
		data = data[:min(int64(len(data)), count*bs)]
	}
	full := int64(len(data)) / bs
	partial := 0
	if int64(len(data))%bs != 0 {
		partial = 1
	}
	if out == "" {
		_, _ = e.Stdout.Write(data)
	} else if err := e.FS.WriteFile(out, data); err != nil {
		e.Errorf("can't open '%s': %s", out, err)
		return 1
	}
	secs := 0.000096 + float64(len(data))/40e6
	fmt.Fprintf(e.Stderr, "%d+%d records in\n%d+%d records out\n%d bytes (%s) copied, %f seconds, %s/s\n",
		full, partial, full, partial, len(data), ddSize(int64(len(data))), secs, ddSize(int64(float64(len(data))/secs)))
	return 0
}

// parseSize parses dd numbers with optional k, M, G suffixes.
func parseSize(v string) (int64, error) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "k"), strings.HasSuffix(v, "K"):
		mult, v = 1024, v[:len(v)-1]
	case strings.HasSuffix(v, "M"):
		mult, v = 1<<20, v[:len(v)-1]
	case strings.HasSuffix(v, "G"):
		mult, v = 1<<30, v[:len(v)-1]
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n * mult, err
}

// ddSize formats a byte count the way BusyBox dd does: 52B, 1.0MB.
func ddSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	f, units := float64(n), "KMGT"
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%cB", f, units[i])
}

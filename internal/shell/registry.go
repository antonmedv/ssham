package shell

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/vfs"
)

// Command is a BusyBox applet.
type Command struct {
	// Name is the applet name, e.g. "ls".
	Name string
	// Aliases are other names for the same applet, e.g. "egrep" for grep.
	Aliases []string
	// Dir is where the applet's link to /bin/busybox lives: /bin (the
	// default), /sbin, /usr/bin or /usr/sbin.
	Dir string
	// Usage is BusyBox's usage text without the applet name, e.g.
	// "[-1AaCxdLHRFplinshrSXvctu] [FILE]...", optionally followed by a
	// blank line and a description. It is shown for --help and by
	// Env.Usage.
	Usage string
	// Run simulates the applet and returns its exit status.
	Run func(e *Env) int
}

// Registry is the set of applets.
type Registry struct {
	cmds map[string]*Command
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{cmds: map[string]*Command{}} }

// Add registers applets. It panics on a mistake (empty or duplicate name,
// no Run), so it shows up as soon as the program starts.
func (r *Registry) Add(cmds ...Command) {
	for _, c := range cmds {
		if c.Dir == "" {
			c.Dir = "/bin"
		}
		if c.Run == nil {
			panic(fmt.Sprintf("shell: command %q has no Run", c.Name))
		}
		for _, name := range append([]string{c.Name}, c.Aliases...) {
			if name == "" {
				panic("shell: command with empty name")
			}
			if _, dup := r.cmds[name]; dup {
				panic(fmt.Sprintf("shell: command %q registered twice", name))
			}
			r.cmds[name] = &c
		}
	}
}

// Lookup returns the command with the given name.
func (r *Registry) Lookup(name string) (*Command, bool) {
	c, ok := r.cmds[name]
	return c, ok
}

// Names returns every registered name, sorted.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.cmds))
	for n := range r.cmds {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Applets returns every applet name BusyBox provides: the registered
// commands plus the shell builtins that are also applets (echo, test, ...),
// with the directory each one is linked from.
func (r *Registry) Applets() map[string]string {
	out := map[string]string{}
	for name, c := range r.cmds {
		out[name] = c.Dir
	}
	for name, b := range builtins {
		if b.dir != "" {
			out[name] = b.dir
		}
	}
	return out
}

// busyboxSize is the size of the multi-call binary.
const busyboxSize = 1007208

// Install puts /bin/busybox and a link to it for every applet into f, the
// way BusyBox's make install does.
func Install(f *vfs.FS, r *Registry) {
	// Same date as the rest of the firmware image.
	mtime := f.Now()
	if bin, err := f.Stat("root", path.Dir(busyboxPath)); err == nil {
		mtime = bin.ModTime
	}
	bb := rootfs.Binary(busyboxSize)
	bb.ModTime = mtime
	f.Put(busyboxPath, bb)
	for name, dir := range r.Applets() {
		if name == "busybox" {
			continue
		}
		f.Put(dir+"/"+name, &vfs.Node{Mode: fs.ModeSymlink | 0o777, Owner: "root", Group: "root", ModTime: mtime, Target: linkTarget(dir)})
	}
}

// linkTarget returns the relative link to /bin/busybox from dir:
// "busybox" in /bin, "../bin/busybox" in /sbin, "../../bin/busybox" in
// /usr/bin.
func linkTarget(dir string) string {
	if dir == path.Dir(busyboxPath) {
		return path.Base(busyboxPath)
	}
	depth := strings.Count(strings.Trim(dir, "/"), "/") + 1
	return strings.Repeat("../", depth) + strings.TrimPrefix(busyboxPath, "/")
}

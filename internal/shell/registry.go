package shell

import (
	"fmt"
	"hash/fnv"
	"sort"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

// Command is a simulated program.
type Command struct {
	// Name is the program name, e.g. "ls".
	Name string
	// Aliases are other names for the same program, e.g. "egrep" for grep.
	Aliases []string
	// Dir is where the binary is installed. Defaults to /usr/bin.
	Dir string
	// Run simulates the program and returns its exit status. A nil Run
	// means the program is installed but silently does nothing.
	Run func(e *Env) int
}

// Registry is the set of simulated programs.
type Registry struct {
	cmds map[string]*Command
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{cmds: map[string]*Command{}} }

// Add registers commands. It panics on an empty or duplicate name, so
// mistakes show up as soon as the program starts.
func (r *Registry) Add(cmds ...Command) {
	for _, c := range cmds {
		if c.Dir == "" {
			c.Dir = "/usr/bin"
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

// Install puts a stub binary for every command, and for builtins that also
// exist as programs (echo, test, ...), into f.
func Install(f *vfs.FS, r *Registry) {
	put := func(dir, name string) {
		f.Put(dir+"/"+name, &vfs.Node{
			Mode: 0o755, Owner: "root", Group: "root", ModTime: f.Now().Add(-120 * 24 * time.Hour).Truncate(time.Minute),
			Data:     []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00"),
			FakeSize: fakeSize(name),
		})
	}
	for name, c := range r.cmds {
		put(c.Dir, name)
	}
	for name, b := range builtins {
		if b.binary {
			put("/usr/bin", name)
		}
	}
	// setuid binaries
	for _, p := range []string{"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su"} {
		if n, err := f.Stat("root", p); err == nil {
			n.Mode |= 0o4000
		}
	}
}

// fakeSize gives each stub binary a stable, plausible size.
func fakeSize(name string) int64 {
	h := fnv.New32a()
	h.Write([]byte(name))
	return 35000 + int64(h.Sum32()%240000)
}

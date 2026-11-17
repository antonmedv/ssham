// Package vfs implements the in-memory filesystem that the fake shell
// operates on. Nothing here touches the host filesystem.
package vfs

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors returned by filesystem operations. Their messages match what GNU
// coreutils prints, so commands can show them verbatim.
var (
	ErrNotExist   = errors.New("No such file or directory")
	ErrPermission = errors.New("Permission denied")
	ErrIsDir      = errors.New("Is a directory")
	ErrNotDir     = errors.New("Not a directory")
	ErrExist      = errors.New("File exists")
	ErrNotEmpty   = errors.New("Directory not empty")
	ErrNoSpace    = errors.New("No space left on device")
	ErrLoop       = errors.New("Too many levels of symbolic links")
	ErrInvalid    = errors.New("Invalid argument")
	ErrReadOnly   = errors.New("Read-only file system")
	ErrBusy       = errors.New("Device or resource busy")
)

// Default per-session quotas. They stop an attacker from exhausting the
// honeypot's memory by writing huge files.
const (
	DefaultMaxBytes = 16 << 20
	DefaultMaxNodes = 20000
	maxLinkDepth    = 16
)

// Node is a file, directory, or symlink.
type Node struct {
	Name     string
	Mode     fs.FileMode
	Owner    string
	Group    string
	ModTime  time.Time
	Data     []byte
	FakeSize int64  // reported size for fake binaries whose Data is a stub
	Target   string // symlink target
	Children map[string]*Node
}

// IsDir reports whether n is a directory.
func (n *Node) IsDir() bool { return n.Mode.IsDir() }

// IsLink reports whether n is a symbolic link.
func (n *Node) IsLink() bool { return n.Mode&fs.ModeSymlink != 0 }

// Size returns the size ls should show.
func (n *Node) Size() int64 {
	switch {
	case n.IsDir():
		return 4096
	case n.IsLink():
		return int64(len(n.Target))
	case n.FakeSize > 0:
		return n.FakeSize
	}
	return int64(len(n.Data))
}

func (n *Node) clone() *Node {
	c := *n
	if n.Data != nil {
		c.Data = append([]byte(nil), n.Data...)
	}
	if n.Children != nil {
		c.Children = make(map[string]*Node, len(n.Children))
		for k, v := range n.Children {
			c.Children[k] = v.clone()
		}
	}
	return &c
}

// FS is an in-memory filesystem. It is safe for concurrent use.
type FS struct {
	mu       sync.RWMutex
	root     *Node
	bytes    int64
	nodes    int
	MaxBytes int64
	MaxNodes int
	Now      func() time.Time
	// Writable lists the mount points that can be changed. Everything
	// else is read-only, like an embedded device's squashfs root. Nil
	// means everything is writable.
	Writable []string
}

// New returns an empty filesystem containing only "/".
func New() *FS {
	return &FS{
		root:     &Node{Name: "/", Mode: fs.ModeDir | 0o755, Owner: "root", Group: "root", ModTime: time.Now(), Children: map[string]*Node{}},
		nodes:    1,
		MaxBytes: DefaultMaxBytes,
		MaxNodes: DefaultMaxNodes,
		Now:      time.Now,
	}
}

// Clone returns a deep copy of the filesystem, so each session can modify
// its own copy without affecting others.
func (f *FS) Clone() *FS {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return &FS{root: f.root.clone(), bytes: f.bytes, nodes: f.nodes, MaxBytes: f.MaxBytes, MaxNodes: f.MaxNodes, Now: f.Now, Writable: f.Writable}
}

// Abs resolves p against cwd and cleans it, without touching the tree.
func Abs(cwd, p string) string {
	if !strings.HasPrefix(p, "/") {
		p = cwd + "/" + p
	}
	return path.Clean(p)
}

func split(p string) []string {
	p = path.Clean("/" + p)
	if p == "/" {
		return nil
	}
	return strings.Split(p[1:], "/")
}

// canAccess checks the permission bits of n for user. want is a mask of
// 4 (read), 2 (write), 1 (execute/search).
func canAccess(n *Node, user string, want fs.FileMode) bool {
	if user == "root" {
		// root may do anything except execute files with no x bit at all.
		if want&1 != 0 && !n.IsDir() && n.Mode.Perm()&0o111 == 0 {
			return false
		}
		return true
	}
	perm := n.Mode.Perm()
	if n.Owner == user {
		return (perm>>6)&want == want
	}
	return perm&want == want
}

// resolve walks to p. If follow is true, a symlink in the final component
// is followed. If user is non-empty, search permission is checked on every
// directory traversed. It returns the node and its canonical path.
func (f *FS) resolve(p, user string, follow bool, depth int) (*Node, string, error) {
	if depth > maxLinkDepth {
		return nil, "", ErrLoop
	}
	parts := split(p)
	cur := f.root
	curPath := "/"
	for i, name := range parts {
		if !cur.IsDir() {
			return nil, "", ErrNotDir
		}
		if user != "" && !canAccess(cur, user, 1) {
			return nil, "", ErrPermission
		}
		next, ok := cur.Children[name]
		if !ok {
			return nil, "", ErrNotExist
		}
		last := i == len(parts)-1
		if next.IsLink() && (!last || follow) {
			target := next.Target
			if !strings.HasPrefix(target, "/") {
				target = path.Join(curPath, target)
			}
			rest := strings.Join(parts[i+1:], "/")
			return f.resolve(path.Join(target, rest), user, follow, depth+1)
		}
		cur = next
		curPath = path.Join(curPath, name)
	}
	return cur, curPath, nil
}

// Stat returns the node at p, following symlinks.
func (f *FS) Stat(user, p string) (*Node, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, _, err := f.resolve(p, user, true, 0)
	return n, err
}

// Lstat returns the node at p without following a final symlink.
func (f *FS) Lstat(user, p string) (*Node, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, _, err := f.resolve(p, user, false, 0)
	return n, err
}

// Realpath returns the canonical path of p with all symlinks resolved.
func (f *FS) Realpath(user, p string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, rp, err := f.resolve(p, user, true, 0)
	return rp, err
}

// CanAccess reports whether user has the given permission bits on n.
func CanAccess(n *Node, user string, want fs.FileMode) bool { return canAccess(n, user, want) }

// ReadFile returns the contents of the file at p.
func (f *FS) ReadFile(user, p string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, _, err := f.resolve(p, user, true, 0)
	if err != nil {
		return nil, err
	}
	if n.IsDir() {
		return nil, ErrIsDir
	}
	if !canAccess(n, user, 4) {
		return nil, ErrPermission
	}
	return append([]byte(nil), n.Data...), nil
}

// ReadDir returns the entries of the directory at p, sorted by name.
func (f *FS) ReadDir(user, p string) ([]*Node, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, _, err := f.resolve(p, user, true, 0)
	if err != nil {
		return nil, err
	}
	if !n.IsDir() {
		return nil, ErrNotDir
	}
	if !canAccess(n, user, 4) {
		return nil, ErrPermission
	}
	out := make([]*Node, 0, len(n.Children))
	for _, c := range n.Children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// readOnly reports whether the canonical path p is on a read-only mount.
func (f *FS) readOnly(p string) bool {
	if f.Writable == nil {
		return false
	}
	for _, w := range f.Writable {
		if p == w || strings.HasPrefix(p, strings.TrimSuffix(w, "/")+"/") {
			return false
		}
	}
	return true
}

// isMountPoint reports whether the canonical path p is a writable mount's
// root, which cannot be removed or renamed.
func (f *FS) isMountPoint(p string) bool {
	for _, w := range f.Writable {
		if p == w {
			return true
		}
	}
	return false
}

// IsReadOnly reports whether p is on a read-only mount.
func (f *FS) IsReadOnly(p string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, cp, err := f.resolve(p, "", true, 0); err == nil {
		p = cp
	}
	return f.readOnly(p)
}

// parentFor resolves the directory that will contain p and checks that
// user may write to it.
func (f *FS) parentFor(user, p string) (*Node, string, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		return nil, "", ErrExist
	}
	dir, name := path.Split(p)
	parent, dirPath, err := f.resolve(dir, user, true, 0)
	if err != nil {
		return nil, "", err
	}
	if !parent.IsDir() {
		return nil, "", ErrNotDir
	}
	if !canAccess(parent, user, 3) {
		return nil, "", ErrPermission
	}
	if f.readOnly(path.Join(dirPath, name)) {
		return nil, "", ErrReadOnly
	}
	return parent, name, nil
}

func (f *FS) addNode(parent *Node, n *Node) error {
	if f.nodes >= f.MaxNodes {
		return ErrNoSpace
	}
	if f.bytes+int64(len(n.Data)) > f.MaxBytes {
		return ErrNoSpace
	}
	parent.Children[n.Name] = n
	parent.ModTime = f.Now()
	f.nodes++
	f.bytes += int64(len(n.Data))
	return nil
}

// WriteFile creates or overwrites (or appends to) the file at p.
func (f *FS) WriteFile(user, p string, data []byte, appendMode bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p == "/dev/null" {
		return nil
	}
	if n, cp, err := f.resolve(p, user, true, 0); err == nil {
		if n.IsDir() {
			return ErrIsDir
		}
		if !canAccess(n, user, 2) {
			return ErrPermission
		}
		if f.readOnly(cp) {
			return ErrReadOnly
		}
		newData := data
		if appendMode {
			newData = append(append([]byte(nil), n.Data...), data...)
		}
		delta := int64(len(newData) - len(n.Data))
		if f.bytes+delta > f.MaxBytes {
			return ErrNoSpace
		}
		f.bytes += delta
		n.Data = newData
		n.FakeSize = 0
		n.ModTime = f.Now()
		return nil
	} else if !errors.Is(err, ErrNotExist) {
		return err
	}
	// A dangling symlink: write to its target instead.
	if l, _, err := f.resolve(p, user, false, 0); err == nil && l.IsLink() {
		target := l.Target
		if !strings.HasPrefix(target, "/") {
			target = path.Join(path.Dir(p), target)
		}
		f.mu.Unlock()
		defer f.mu.Lock()
		return f.WriteFile(user, target, data, appendMode)
	}
	parent, name, err := f.parentFor(user, p)
	if err != nil {
		return err
	}
	return f.addNode(parent, &Node{
		Name: name, Mode: 0o644, Owner: user, Group: user,
		ModTime: f.Now(), Data: append([]byte(nil), data...),
	})
}

// Mkdir creates a directory. With parents, missing parents are created and
// an existing directory is not an error.
func (f *FS) Mkdir(user, p string, parents bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if parents {
		cur := "/"
		for _, part := range split(p) {
			cur = path.Join(cur, part)
			n, _, err := f.resolve(cur, user, true, 0)
			if err == nil {
				if !n.IsDir() {
					return ErrNotDir
				}
				continue
			}
			if !errors.Is(err, ErrNotExist) {
				return err
			}
			if err := f.mkdirLocked(user, cur); err != nil {
				return err
			}
		}
		return nil
	}
	if _, _, err := f.resolve(p, user, false, 0); err == nil {
		return ErrExist
	}
	return f.mkdirLocked(user, p)
}

func (f *FS) mkdirLocked(user, p string) error {
	parent, name, err := f.parentFor(user, p)
	if err != nil {
		return err
	}
	return f.addNode(parent, &Node{
		Name: name, Mode: fs.ModeDir | 0o755, Owner: user, Group: user,
		ModTime: f.Now(), Children: map[string]*Node{},
	})
}

// Symlink creates a symbolic link at p pointing to target.
func (f *FS) Symlink(user, target, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, _, err := f.resolve(p, user, false, 0); err == nil {
		return ErrExist
	}
	parent, name, err := f.parentFor(user, p)
	if err != nil {
		return err
	}
	return f.addNode(parent, &Node{
		Name: name, Mode: fs.ModeSymlink | 0o777, Owner: user, Group: user,
		ModTime: f.Now(), Target: target,
	})
}

func countTree(n *Node) (nodes int, bytes int64) {
	nodes, bytes = 1, int64(len(n.Data))
	for _, c := range n.Children {
		cn, cb := countTree(c)
		nodes += cn
		bytes += cb
	}
	return
}

// Remove deletes the node at p. Non-empty directories need recursive.
func (f *FS) Remove(user, p string, recursive bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, cp, err := f.resolve(p, user, false, 0)
	if err != nil {
		return err
	}
	if n == f.root {
		return ErrPermission
	}
	if n.IsDir() && !recursive {
		return ErrIsDir
	}
	if f.isMountPoint(cp) {
		return ErrBusy
	}
	parent, name, err := f.parentFor(user, p)
	if err != nil {
		return err
	}
	delete(parent.Children, name)
	parent.ModTime = f.Now()
	cn, cb := countTree(n)
	f.nodes -= cn
	f.bytes -= cb
	return nil
}

// Rmdir removes an empty directory.
func (f *FS) Rmdir(user, p string) error {
	f.mu.RLock()
	n, _, err := f.resolve(p, user, false, 0)
	f.mu.RUnlock()
	if err != nil {
		return err
	}
	if !n.IsDir() {
		return ErrNotDir
	}
	if len(n.Children) > 0 {
		return ErrNotEmpty
	}
	return f.Remove(user, p, true)
}

// Rename moves src to dst. If dst is an existing directory, src is moved
// inside it.
func (f *FS) Rename(user, src, dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, cp, err := f.resolve(src, user, false, 0)
	if err != nil {
		return err
	}
	if f.isMountPoint(cp) {
		return ErrBusy
	}
	if d, _, err := f.resolve(dst, user, true, 0); err == nil && d.IsDir() {
		dst = path.Join(dst, n.Name)
	}
	if strings.HasPrefix(path.Clean(dst)+"/", path.Clean(src)+"/") {
		return ErrInvalid
	}
	sp, sname, err := f.parentFor(user, src)
	if err != nil {
		return err
	}
	dp, dname, err := f.parentFor(user, dst)
	if err != nil {
		return err
	}
	if old, ok := dp.Children[dname]; ok {
		cn, cb := countTree(old)
		f.nodes -= cn
		f.bytes -= cb
	}
	delete(sp.Children, sname)
	n.Name = dname
	dp.Children[dname] = n
	dp.ModTime = f.Now()
	return nil
}

// Copy copies src to dst. Directories need recursive.
func (f *FS) Copy(user, src, dst string, recursive bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, _, err := f.resolve(src, user, true, 0)
	if err != nil {
		return err
	}
	if n.IsDir() && !recursive {
		return ErrIsDir
	}
	if !canAccess(n, user, 4) {
		return ErrPermission
	}
	if d, _, err := f.resolve(dst, user, true, 0); err == nil && d.IsDir() {
		dst = path.Join(dst, n.Name)
	}
	if d, dp, err := f.resolve(dst, user, true, 0); err == nil && !d.IsDir() && !n.IsDir() {
		if !canAccess(d, user, 2) {
			return ErrPermission
		}
		if f.readOnly(dp) {
			return ErrReadOnly
		}
		delta := int64(len(n.Data) - len(d.Data))
		if f.bytes+delta > f.MaxBytes {
			return ErrNoSpace
		}
		f.bytes += delta
		d.Data = append([]byte(nil), n.Data...)
		d.FakeSize = n.FakeSize
		d.ModTime = f.Now()
		return nil
	}
	parent, name, err := f.parentFor(user, dst)
	if err != nil {
		return err
	}
	c := n.clone()
	c.Name = name
	c.Owner, c.Group = user, user
	c.ModTime = f.Now()
	cn, cb := countTree(c)
	if f.nodes+cn > f.MaxNodes || f.bytes+cb > f.MaxBytes {
		return ErrNoSpace
	}
	parent.Children[name] = c
	f.nodes += cn
	f.bytes += cb
	return nil
}

// Chmod changes the permission bits of p.
func (f *FS) Chmod(user, p string, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, cp, err := f.resolve(p, user, true, 0)
	if err != nil {
		return err
	}
	if user != "root" && n.Owner != user {
		return errors.New("Operation not permitted")
	}
	if f.readOnly(cp) {
		return ErrReadOnly
	}
	n.Mode = (n.Mode &^ 0o7777) | (mode & 0o7777)
	return nil
}

// Chown changes the owner and group of p. Only root may do this.
func (f *FS) Chown(user, p, owner, group string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, cp, err := f.resolve(p, user, true, 0)
	if err != nil {
		return err
	}
	if user != "root" {
		return errors.New("Operation not permitted")
	}
	if f.readOnly(cp) {
		return ErrReadOnly
	}
	if owner != "" {
		n.Owner = owner
	}
	if group != "" {
		n.Group = group
	}
	return nil
}

// Touch updates the modification time of p, creating it if needed.
func (f *FS) Touch(user, p string) error {
	f.mu.Lock()
	n, cp, err := f.resolve(p, user, true, 0)
	if err == nil {
		defer f.mu.Unlock()
		if !canAccess(n, user, 2) {
			return ErrPermission
		}
		if f.readOnly(cp) {
			return ErrReadOnly
		}
		n.ModTime = f.Now()
		return nil
	}
	f.mu.Unlock()
	if !errors.Is(err, ErrNotExist) {
		return err
	}
	return f.WriteFile(user, p, nil, true)
}

// Put inserts a node at p with no permission checks, creating parent
// directories owned by root as needed. It is used to build the seed tree.
func (f *FS) Put(p string, n *Node) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := split(p)
	cur := f.root
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur.Children[part]
		if !ok {
			next = &Node{Name: part, Mode: fs.ModeDir | 0o755, Owner: "root", Group: "root", ModTime: cur.ModTime, Children: map[string]*Node{}}
			cur.Children[part] = next
			f.nodes++
		}
		cur = next
	}
	n.Name = parts[len(parts)-1]
	if n.IsDir() && n.Children == nil {
		n.Children = map[string]*Node{}
	}
	if old, ok := cur.Children[n.Name]; ok {
		if old.IsDir() && n.IsDir() {
			// Keep existing children when re-declaring a directory.
			n.Children = old.Children
		}
		cn, cb := countTree(old)
		f.nodes -= cn
		f.bytes -= cb
	}
	cur.Children[n.Name] = n
	cn, cb := countTree(n)
	f.nodes += cn
	f.bytes += cb
}

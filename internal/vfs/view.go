package vfs

import "io/fs"

// Access bits for CanAccess.
const (
	Exec  fs.FileMode = 1
	Write fs.FileMode = 2
	Read  fs.FileMode = 4
)

// View is the filesystem as one user sees it from one working directory.
// Relative paths resolve against Cwd and permissions are checked as User.
// Commands use a View so they never have to think about either.
type View struct {
	fs   *FS
	User string
	Cwd  string
	// Endless, if set, is called when a read hits a device that never
	// ends, like /dev/urandom: the read returns only a first part.
	Endless func()
}

// IsEndless reports whether reading n never ends.
func IsEndless(n *Node) bool { return n.Device == DevZero || n.Device == DevRandom }

// As returns a view of f for user, with relative paths resolved against cwd.
func (f *FS) As(user, cwd string) *View {
	return &View{fs: f, User: user, Cwd: cwd}
}

// AsRoot returns the same view with root privileges, for commands that
// write system files on the user's behalf (crontab, useradd, ...).
func (v *View) AsRoot() *View {
	r := v.fs.As("root", v.Cwd)
	r.Endless = v.Endless
	return r
}

// FS is the underlying filesystem, for helpers that take one.
func (v *View) FS() *FS { return v.fs }

// Abs resolves p against the working directory.
func (v *View) Abs(p string) string { return Abs(v.Cwd, p) }

// Can reports whether the user has the given access to n.
func (v *View) Can(n *Node, want fs.FileMode) bool { return canAccess(n, v.User, want) }

// Stat returns the node at p, following symlinks.
func (v *View) Stat(p string) (*Node, error) { return v.fs.Stat(v.User, v.Abs(p)) }

// Lstat returns the node at p without following a final symlink.
func (v *View) Lstat(p string) (*Node, error) { return v.fs.Lstat(v.User, v.Abs(p)) }

// Realpath returns the canonical path of p.
func (v *View) Realpath(p string) (string, error) { return v.fs.Realpath(v.User, v.Abs(p)) }

// ReadFile returns the contents of the file at p.
func (v *View) ReadFile(p string) ([]byte, error) {
	if v.Endless != nil {
		if n, err := v.fs.Stat(v.User, v.Abs(p)); err == nil && IsEndless(n) {
			v.Endless()
		}
	}
	return v.fs.ReadFile(v.User, v.Abs(p))
}

// ReadDir returns the entries of the directory at p, sorted by name.
func (v *View) ReadDir(p string) ([]*Node, error) { return v.fs.ReadDir(v.User, v.Abs(p)) }

// WriteFile creates or truncates the file at p and writes data to it.
func (v *View) WriteFile(p string, data []byte) error {
	return v.fs.WriteFile(v.User, v.Abs(p), data, false)
}

// AppendFile appends data to the file at p, creating it if needed.
func (v *View) AppendFile(p string, data []byte) error {
	return v.fs.WriteFile(v.User, v.Abs(p), data, true)
}

// Mkdir creates a directory; with parents, like mkdir -p.
func (v *View) Mkdir(p string, parents bool) error { return v.fs.Mkdir(v.User, v.Abs(p), parents) }

// Remove deletes p; directories need recursive.
func (v *View) Remove(p string, recursive bool) error {
	return v.fs.Remove(v.User, v.Abs(p), recursive)
}

// Rmdir removes an empty directory.
func (v *View) Rmdir(p string) error { return v.fs.Rmdir(v.User, v.Abs(p)) }

// Rename moves src to dst, or into dst if it is a directory.
func (v *View) Rename(src, dst string) error { return v.fs.Rename(v.User, v.Abs(src), v.Abs(dst)) }

// Copy copies src to dst, or into dst if it is a directory.
func (v *View) Copy(src, dst string, recursive bool) error {
	return v.fs.Copy(v.User, v.Abs(src), v.Abs(dst), recursive)
}

// Symlink creates a symbolic link at p pointing to target.
func (v *View) Symlink(target, p string) error { return v.fs.Symlink(v.User, target, v.Abs(p)) }

// Chmod changes the permission bits of p.
func (v *View) Chmod(p string, mode fs.FileMode) error { return v.fs.Chmod(v.User, v.Abs(p), mode) }

// Chown changes the owner and group of p. Empty values are left unchanged.
func (v *View) Chown(p, owner, group string) error {
	return v.fs.Chown(v.User, v.Abs(p), owner, group)
}

// Touch updates the modification time of p, creating it if needed.
func (v *View) Touch(p string) error { return v.fs.Touch(v.User, v.Abs(p)) }

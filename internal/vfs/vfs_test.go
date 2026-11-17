package vfs

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// newTestFS builds a small tree:
//
//	/etc/passwd   root 0644
//	/etc/shadow   root 0640
//	/root/        root 0700
//	/home/alice/  alice 0755
//	/tmp/         root 1777
//	/bin -> usr/bin
func newTestFS() *FS {
	f := New()
	f.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	dir := func(p string, mode fs.FileMode, owner string) {
		f.Put(p, &Node{Mode: fs.ModeDir | mode, Owner: owner, Group: owner})
	}
	file := func(p string, mode fs.FileMode, owner, data string) {
		f.Put(p, &Node{Mode: mode, Owner: owner, Group: owner, Data: []byte(data)})
	}
	dir("/etc", 0o755, "root")
	file("/etc/passwd", 0o644, "root", "root:x:0:0\n")
	file("/etc/shadow", 0o640, "root", "secret")
	dir("/root", 0o700, "root")
	file("/root/notes", 0o644, "root", "hidden")
	dir("/home/alice", 0o755, "alice")
	dir("/tmp", 0o1777, "root")
	dir("/usr/bin", 0o755, "root")
	file("/usr/bin/ls", 0o755, "root", "\x7fELF")
	f.Put("/bin", &Node{Mode: fs.ModeSymlink | 0o777, Owner: "root", Target: "usr/bin"})
	return f
}

func TestPermissions(t *testing.T) {
	f := newTestFS()
	tests := []struct {
		user, op, path string
		want           error
	}{
		{"alice", "read", "/etc/passwd", nil},
		{"alice", "read", "/etc/shadow", ErrPermission},
		{"root", "read", "/etc/shadow", nil},
		{"alice", "read", "/root/notes", ErrPermission}, // no search permission on /root
		{"alice", "list", "/root", ErrPermission},
		{"alice", "write", "/etc/passwd", ErrPermission},
		{"alice", "write", "/etc/new", ErrPermission},
		{"alice", "write", "/home/alice/f", nil},
		{"alice", "write", "/tmp/f", nil},
		{"root", "write", "/etc/new", nil},
		{"alice", "read", "/nope", ErrNotExist},
		{"alice", "read", "/etc", ErrIsDir},
		{"alice", "read", "/etc/passwd/x", ErrNotDir},
		{"alice", "remove", "/etc/passwd", ErrPermission},
	}
	for _, tt := range tests {
		var err error
		switch tt.op {
		case "read":
			_, err = f.ReadFile(tt.user, tt.path)
		case "list":
			_, err = f.ReadDir(tt.user, tt.path)
		case "write":
			err = f.WriteFile(tt.user, tt.path, []byte("x"), false)
		case "remove":
			err = f.Remove(tt.user, tt.path, false)
		}
		if !errors.Is(err, tt.want) {
			t.Errorf("%s %s %s: got %v, want %v", tt.user, tt.op, tt.path, err, tt.want)
		}
	}
}

func TestNewFilesBelongToTheirCreator(t *testing.T) {
	f := newTestFS()
	if err := f.WriteFile("alice", "/tmp/a", []byte("hi"), false); err != nil {
		t.Fatal(err)
	}
	n, _ := f.Stat("root", "/tmp/a")
	if n.Owner != "alice" || n.Mode.Perm() != 0o644 {
		t.Errorf("new file: owner %s mode %o", n.Owner, n.Mode.Perm())
	}
	// Now only alice (and root) may write it.
	if err := f.WriteFile("bob", "/tmp/a", []byte("x"), false); !errors.Is(err, ErrPermission) {
		t.Errorf("bob overwrote alice's file: %v", err)
	}
}

func TestSymlinks(t *testing.T) {
	f := newTestFS()
	if data, err := f.ReadFile("root", "/bin/ls"); err != nil || string(data) != "\x7fELF" {
		t.Errorf("read through relative link: %q %v", data, err)
	}
	if p, _ := f.Realpath("root", "/bin/ls"); p != "/usr/bin/ls" {
		t.Errorf("Realpath = %s", p)
	}
	if n, _ := f.Lstat("root", "/bin"); !n.IsLink() {
		t.Error("Lstat followed the link")
	}

	f.Symlink("root", "/tmp/b", "/tmp/a")
	f.Symlink("root", "/tmp/a", "/tmp/b")
	if _, err := f.Stat("root", "/tmp/a"); !errors.Is(err, ErrLoop) {
		t.Errorf("loop: %v", err)
	}

	// Writing through a dangling link creates its target.
	f.Symlink("root", "/tmp/target", "/tmp/dangling")
	if err := f.WriteFile("root", "/tmp/dangling", []byte("x"), false); err != nil {
		t.Fatal(err)
	}
	if data, _ := f.ReadFile("root", "/tmp/target"); string(data) != "x" {
		t.Errorf("target = %q", data)
	}
}

func TestAppendTruncateTouch(t *testing.T) {
	f := newTestFS()
	f.WriteFile("root", "/tmp/f", []byte("a"), false)
	f.WriteFile("root", "/tmp/f", []byte("b"), true)
	if data, _ := f.ReadFile("root", "/tmp/f"); string(data) != "ab" {
		t.Errorf("append: %q", data)
	}
	f.WriteFile("root", "/tmp/f", []byte("c"), false)
	if data, _ := f.ReadFile("root", "/tmp/f"); string(data) != "c" {
		t.Errorf("truncate: %q", data)
	}
	if err := f.Touch("alice", "/tmp/new"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat("alice", "/tmp/new"); err != nil {
		t.Error("touch did not create the file")
	}
	if err := f.WriteFile("root", "/dev/null", []byte("gone"), false); err != nil {
		t.Errorf("/dev/null: %v", err)
	}
}

func TestMkdirRemoveRename(t *testing.T) {
	f := newTestFS()
	if err := f.Mkdir("root", "/tmp/a/b/c", false); !errors.Is(err, ErrNotExist) {
		t.Errorf("mkdir without -p: %v", err)
	}
	if err := f.Mkdir("root", "/tmp/a/b/c", true); err != nil {
		t.Fatal(err)
	}
	if err := f.Mkdir("root", "/tmp/a", false); !errors.Is(err, ErrExist) {
		t.Errorf("mkdir existing: %v", err)
	}
	if err := f.Mkdir("root", "/tmp/a", true); err != nil {
		t.Errorf("mkdir -p existing: %v", err)
	}
	if err := f.Rmdir("root", "/tmp/a"); !errors.Is(err, ErrNotEmpty) {
		t.Errorf("rmdir non-empty: %v", err)
	}
	if err := f.Remove("root", "/tmp/a", false); !errors.Is(err, ErrIsDir) {
		t.Errorf("rm dir: %v", err)
	}

	f.WriteFile("root", "/tmp/f", []byte("x"), false)
	if err := f.Rename("root", "/tmp/f", "/tmp/a"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat("root", "/tmp/a/f"); err != nil {
		t.Error("rename into a directory should move the file inside it")
	}
	if err := f.Rename("root", "/tmp/a", "/tmp/a/b/inside"); !errors.Is(err, ErrInvalid) {
		t.Errorf("rename into own subdirectory: %v", err)
	}
	if err := f.Remove("root", "/tmp/a", true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat("root", "/tmp/a/b/c"); !errors.Is(err, ErrNotExist) {
		t.Error("rm -r left children behind")
	}
}

func TestCopy(t *testing.T) {
	f := newTestFS()
	if err := f.Copy("alice", "/etc", "/tmp/etc", false); !errors.Is(err, ErrIsDir) {
		t.Errorf("copy dir without -r: %v", err)
	}
	if err := f.Copy("alice", "/etc/shadow", "/tmp/s", false); !errors.Is(err, ErrPermission) {
		t.Errorf("copy unreadable: %v", err)
	}
	if err := f.Copy("root", "/etc", "/tmp/etc", true); err != nil {
		t.Fatal(err)
	}
	n, _ := f.Stat("root", "/tmp/etc/shadow")
	if n.Owner != "root" || string(n.Data) != "secret" {
		t.Errorf("copied file: %+v", n)
	}
	// Copies are independent.
	f.WriteFile("root", "/tmp/etc/passwd", []byte("changed"), false)
	if data, _ := f.ReadFile("root", "/etc/passwd"); strings.Contains(string(data), "changed") {
		t.Error("copy shares data with the original")
	}
}

func TestChmodChown(t *testing.T) {
	f := newTestFS()
	f.WriteFile("alice", "/tmp/a", nil, false)
	if err := f.Chmod("alice", "/tmp/a", 0o4755); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Stat("root", "/tmp/a"); n.Mode&0o7777 != 0o4755 {
		t.Errorf("mode = %o", n.Mode&0o7777)
	}
	if err := f.Chmod("alice", "/etc/passwd", 0o777); err == nil {
		t.Error("alice changed root's file mode")
	}
	if err := f.Chown("alice", "/tmp/a", "root", ""); err == nil {
		t.Error("non-root chown succeeded")
	}
	if err := f.Chown("root", "/tmp/a", "bob", "staff"); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Stat("root", "/tmp/a"); n.Owner != "bob" || n.Group != "staff" {
		t.Errorf("chown: %s:%s", n.Owner, n.Group)
	}
}

func TestQuota(t *testing.T) {
	f := newTestFS()
	f.MaxBytes = f.bytes + 10
	if err := f.WriteFile("root", "/tmp/a", make([]byte, 8), false); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteFile("root", "/tmp/a", make([]byte, 4), true); !errors.Is(err, ErrNoSpace) {
		t.Errorf("over byte quota: %v", err)
	}
	// Deleting frees space again.
	f.Remove("root", "/tmp/a", false)
	if err := f.WriteFile("root", "/tmp/b", make([]byte, 10), false); err != nil {
		t.Errorf("after delete: %v", err)
	}

	f.MaxNodes = f.nodes + 1
	if err := f.Mkdir("root", "/tmp/d1", false); err != nil {
		t.Fatal(err)
	}
	if err := f.Mkdir("root", "/tmp/d2", false); !errors.Is(err, ErrNoSpace) {
		t.Errorf("over node quota: %v", err)
	}
	if err := f.Copy("root", "/etc", "/tmp/etc", true); !errors.Is(err, ErrNoSpace) {
		t.Errorf("recursive copy over quota: %v", err)
	}
}

func TestCloneIsIndependent(t *testing.T) {
	a := newTestFS()
	b := a.Clone()
	a.Remove("root", "/etc", true)
	a.WriteFile("root", "/tmp/x", []byte("x"), false)
	if _, err := b.Stat("root", "/etc/passwd"); err != nil {
		t.Error("clone lost a file deleted from the original")
	}
	if _, err := b.Stat("root", "/tmp/x"); err == nil {
		t.Error("clone sees a file created in the original")
	}
}

func TestView(t *testing.T) {
	f := newTestFS()
	v := f.As("alice", "/home/alice")
	if err := v.WriteFile("notes.txt", []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := v.AppendFile("./notes.txt", []byte("!")); err != nil {
		t.Fatal(err)
	}
	if data, _ := f.ReadFile("root", "/home/alice/notes.txt"); string(data) != "hi!" {
		t.Errorf("relative write: %q", data)
	}
	if v.Abs("../bob/../alice/x") != "/home/alice/x" {
		t.Errorf("Abs = %s", v.Abs("../bob/../alice/x"))
	}
	if _, err := v.ReadFile("/etc/shadow"); !errors.Is(err, ErrPermission) {
		t.Errorf("view ignores permissions: %v", err)
	}
	if _, err := v.AsRoot().ReadFile("/etc/shadow"); err != nil {
		t.Errorf("AsRoot: %v", err)
	}
}

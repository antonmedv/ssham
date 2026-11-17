package rootfs

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

var host = Host{Hostname: "cam01", Kernel: "4.9.37", Booted: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}

func TestBuild(t *testing.T) {
	f, err := Build(host)
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) string {
		t.Helper()
		b, err := f.ReadFile("root", p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(b)
	}
	if got := read("/etc/hostname"); got != "cam01\n" {
		t.Errorf("/etc/hostname = %q", got)
	}
	if got := read("/proc/version"); !strings.HasPrefix(got, "Linux version 4.9.37 ") {
		t.Errorf("/proc/version = %q", got)
	}
	if !strings.HasPrefix(read("/etc/shadow"), "root:$1$") {
		t.Error("/etc/shadow does not lead to the shadow file on flash")
	}
	if _, err := f.ReadFile("root", "/etc/hostname.tmpl"); err == nil {
		t.Error("template file leaked into the image")
	}

	for p, want := range modes {
		n, err := f.Lstat("root", p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if n.Mode&0o7777 != want.mode || n.Owner != want.owner {
			t.Errorf("%s: mode %o owner %s, want %o %s", p, n.Mode&0o7777, n.Owner, want.mode, want.owner)
		}
	}
	for p, target := range links {
		if n, err := f.Lstat("root", p); err != nil || n.Target != target {
			t.Errorf("link %s: %v %+v", p, err, n)
		}
		if _, err := f.Stat("root", p); err != nil {
			t.Errorf("link %s -> %s dangles: %v", p, target, err)
		}
	}
	for _, p := range dirs {
		if n, err := f.Stat("root", p); err != nil || !n.IsDir() {
			t.Errorf("dir %s: %v", p, err)
		}
	}
}

func TestRootIsReadOnly(t *testing.T) {
	f, _ := Build(host)
	for _, p := range []string{"/etc/passwd", "/bin/x", "/root/.ssh"} {
		if err := f.WriteFile("root", p, []byte("x"), false); err != vfs.ErrReadOnly {
			t.Errorf("write %s: %v, want read-only", p, err)
		}
	}
	for _, p := range []string{"/tmp/x", "/var/run/x", "/mnt/mtd/x", "/etc/shadow"} {
		if err := f.WriteFile("root", p, []byte("x"), true); err != nil {
			t.Errorf("write %s: %v", p, err)
		}
	}
}

func TestBinaryIsARM(t *testing.T) {
	n := Binary(1000)
	if n.Size() != 1000 || len(n.Data) != 52 {
		t.Fatalf("size %d, header %d bytes", n.Size(), len(n.Data))
	}
	if !bytes.HasPrefix(n.Data, []byte("\x7fELF\x01\x01")) {
		t.Error("not a 32-bit little-endian ELF")
	}
	if machine := binary.LittleEndian.Uint16(n.Data[18:]); machine != 40 {
		t.Errorf("e_machine = %d, want 40 (ARM)", machine)
	}
}

func TestModesReferToRealPaths(t *testing.T) {
	// A typo in the modes table would silently create an empty file.
	f, _ := Build(host)
	for p := range modes {
		n, _ := f.Lstat("root", p)
		if !n.IsDir() && len(n.Data) == 0 && !strings.HasPrefix(p, "/dev/") {
			t.Errorf("%s is listed in modes but has no content in files/", p)
		}
	}
}

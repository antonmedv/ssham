package rootfs

import (
	"strings"
	"testing"
	"time"
)

var host = Host{Hostname: "web01", Kernel: "6.8.0-48-generic", Booted: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}

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

	if got := read("/etc/hostname"); got != "web01\n" {
		t.Errorf("/etc/hostname = %q", got)
	}
	if got := read("/proc/version"); !strings.Contains(got, "Linux version 6.8.0-48-generic") {
		t.Errorf("/proc/version = %q", got)
	}
	if !strings.Contains(read("/root/.bashrc"), "alias ll=") {
		t.Error("dotfiles are not embedded")
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
	}
	for _, p := range dirs {
		if n, err := f.Stat("root", p); err != nil || !n.IsDir() {
			t.Errorf("dir %s: %v", p, err)
		}
	}
	if _, err := f.ReadFile("root", "/etc/hostname.tmpl"); err == nil {
		t.Error("template file leaked into the image")
	}
}

func TestModesReferToRealPaths(t *testing.T) {
	// A typo in the modes table would silently create an empty file.
	f, _ := Build(host)
	for p := range modes {
		n, _ := f.Lstat("root", p)
		if !n.IsDir() && len(n.Data) == 0 && !strings.HasPrefix(p, "/dev/") && !strings.HasPrefix(p, "/var/log/") {
			t.Errorf("%s is listed in modes but has no content in files/", p)
		}
	}
}

func TestAddUser(t *testing.T) {
	f, _ := Build(host)
	if home := AddUser(f, "admin", 1001); home != "/home/admin" {
		t.Errorf("home = %s", home)
	}
	AddUser(f, "admin", 1001) // idempotent

	passwd, _ := f.ReadFile("root", "/etc/passwd")
	if strings.Count(string(passwd), "\nadmin:") != 1 {
		t.Errorf("passwd:\n%s", passwd)
	}
	group, _ := f.ReadFile("root", "/etc/group")
	if !strings.Contains(string(group), "sudo:x:27:ubuntu,admin\n") || !strings.Contains(string(group), "\nadmin:x:1001:\n") {
		t.Errorf("group:\n%s", group)
	}
	if n, err := f.Stat("root", "/home/admin"); err != nil || n.Owner != "admin" || n.Mode&0o777 != 0o750 {
		t.Errorf("home dir: %v %+v", err, n)
	}
	if AddUser(f, "root", 0) != "/root" || AddUser(f, "ubuntu", 1000) != "/home/ubuntu" {
		t.Error("existing users")
	}
}

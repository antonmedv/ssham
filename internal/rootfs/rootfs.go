// Package rootfs builds the disk of the device the honeypot pretends to be:
// a BusyBox-based IP camera with a read-only squashfs root.
//
// The disk lives in files/ as ordinary files, so adding a bait file is just
// a matter of dropping it into the right folder. Files ending in .tmpl are
// rendered with text/template using Host (e.g. {{.Hostname}}). Everything is
// owned by root:root with mode 0644 (files) or 0755 (directories) unless
// listed in modes below.
//
// BusyBox applets (/bin/ls -> busybox, ...) are not listed here: the shell
// package installs one for every command it simulates.
package rootfs

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"io/fs"
	"strings"
	"text/template"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

//go:embed all:files
var files embed.FS

// BusyBox is the version banner of the device's BusyBox.
const BusyBox = "BusyBox v1.31.1 (2021-03-12 11:24:03 CST)"

// Host describes the device.
type Host struct {
	Hostname string
	Kernel   string // e.g. "4.9.37"
	Booted   time.Time
}

// Writable lists the mounts that can be changed. Everything else is the
// read-only squashfs root, even for root.
var Writable = []string{"/dev", "/tmp", "/var", "/mnt/mtd", "/proc/sys/kernel/hostname"}

type attr struct {
	mode  fs.FileMode
	owner string
}

// modes lists paths whose permissions or owner differ from the defaults.
var modes = map[string]attr{
	"/dev/null":                             {0o666, "root"},
	"/dev/zero":                             {0o666, "root"},
	"/dev/random":                           {0o666, "root"},
	"/dev/urandom":                          {0o666, "root"},
	"/dev/tty":                              {0o666, "root"},
	"/dev/console":                          {0o600, "root"},
	"/dev/ttyAMA0":                          {0o660, "root"},
	"/dev/watchdog":                         {0o600, "root"},
	"/etc/init.d/rcS":                       {0o755, "root"},
	"/etc/dropbear/dropbear_ecdsa_host_key": {0o600, "root"},
	"/mnt/mtd/Config/shadow":                {0o600, "root"},
	"/mnt/mtd/Config/Account":               {0o600, "root"},
	"/proc/cpuinfo":                         {0o444, "root"},
	"/proc/meminfo":                         {0o444, "root"},
	"/proc/version":                         {0o444, "root"},
	"/proc/cmdline":                         {0o444, "root"},
	"/proc/mtd":                             {0o444, "root"},
	"/proc/loadavg":                         {0o444, "root"},
	"/proc/mounts":                          {0o444, "root"},
	"/root":                                 {0o700, "root"},
	"/tmp":                                  {0o1777, "root"},
	"/var/tmp":                              {0o1777, "root"},
}

// links lists symbolic links, as path: target.
var links = map[string]string{
	"/etc/shadow":          "/mnt/mtd/Config/shadow", // on flash, so passwords can change
	"/etc/mtab":            "/proc/mounts",
	"/lib/ld-uClibc.so.0":  "ld-uClibc-1.0.31.so",
	"/lib/libc.so.0":       "libuClibc-1.0.31.so",
	"/lib/libm.so.0":       "libm-1.0.31.so",
	"/lib/libpthread.so.0": "libpthread-1.0.31.so",
}

// dirs lists empty directories (git and embed cannot hold those).
var dirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/usr/lib", "/sys",
	"/dev/pts", "/home", "/root",
	"/tmp", "/var/run", "/var/log", "/var/lock", "/var/tmp",
}

// binaries lists programs that are not BusyBox applets, with their size.
var binaries = map[string]int64{
	"/app/ipcam":                1843204,
	"/usr/sbin/dropbear":        326456,
	"/lib/ld-uClibc-1.0.31.so":  27236,
	"/lib/libuClibc-1.0.31.so":  335540,
	"/lib/libm-1.0.31.so":       62948,
	"/lib/libpthread-1.0.31.so": 60072,
	"/usr/lib/libmpi.so":        1028996,
}

// Build returns a fresh filesystem for host. Sessions should Clone it.
func Build(h Host) (*vfs.FS, error) {
	f := vfs.New()
	mtime := h.Booted.Add(-600 * 24 * time.Hour).Truncate(time.Minute)
	if root, err := f.Lstat("root", "/"); err == nil {
		root.ModTime = mtime
	}

	node := func(p string, mode fs.FileMode, data []byte) *vfs.Node {
		a, ok := modes[p]
		if !ok {
			a = attr{mode: mode, owner: "root"}
		}
		n := &vfs.Node{Mode: a.mode, Owner: a.owner, Group: a.owner, ModTime: mtime, Data: data}
		if mode&fs.ModeDir != 0 {
			n.Mode |= fs.ModeDir
		}
		return n
	}

	err := fs.WalkDir(files, "files", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "files" {
			return err
		}
		p := strings.TrimPrefix(name, "files")
		if d.IsDir() {
			f.Put(p, node(p, fs.ModeDir|0o755, nil))
			return nil
		}
		data, err := files.ReadFile(name)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".tmpl") {
			p = strings.TrimSuffix(p, ".tmpl")
			if data, err = render(name, data, h); err != nil {
				return err
			}
		}
		f.Put(p, node(p, 0o644, data))
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range dirs {
		f.Put(p, node(p, fs.ModeDir|0o755, nil))
	}
	for p, target := range links {
		f.Put(p, &vfs.Node{Mode: fs.ModeSymlink | 0o777, Owner: "root", Group: "root", ModTime: mtime, Target: target})
	}
	for p, size := range binaries {
		n := Binary(size)
		n.ModTime = mtime
		f.Put(p, n)
	}
	f.Writable = Writable
	return f, nil
}

// Binary returns an executable whose content starts with a 32-bit ARM ELF
// header, like every program on the device. Bots read that header
// (cat /bin/echo, dd if=/bin/busybox) to pick which payload to download.
// size is the size ls reports.
func Binary(size int64) *vfs.Node {
	var h bytes.Buffer
	h.WriteString("\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00") // ELF32, little endian
	for _, v := range []any{
		uint16(2),           // e_type: executable
		uint16(40),          // e_machine: ARM
		uint32(1),           // e_version
		uint32(0x00011180),  // e_entry
		uint32(52),          // e_phoff
		uint32(size - 1280), // e_shoff
		uint32(0x05000400),  // e_flags: EABI5, hard float
		uint16(52),          // e_ehsize
		uint16(32),          // e_phentsize
		uint16(6),           // e_phnum
		uint16(40),          // e_shentsize
		uint16(28),          // e_shnum
		uint16(27),          // e_shstrndx
	} {
		_ = binary.Write(&h, binary.LittleEndian, v)
	}
	return &vfs.Node{Mode: 0o755, Owner: "root", Group: "root", Data: h.Bytes(), FakeSize: size}
}

func render(name string, data []byte, h Host) ([]byte, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("rootfs: %s: %w", name, err)
	}
	var b bytes.Buffer
	if err := t.Execute(&b, h); err != nil {
		return nil, fmt.Errorf("rootfs: %s: %w", name, err)
	}
	return b.Bytes(), nil
}

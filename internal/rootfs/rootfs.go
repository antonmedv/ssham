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

// Built is when the firmware image was made, just after its BusyBox and
// kernel: every file on the read-only root has this date.
var Built = time.Date(2021, 3, 12, 11, 36, 0, 0, time.FixedZone("CST", 8*3600))

// Host describes the device.
type Host struct {
	Hostname string
	Kernel   string // e.g. "4.9.37"
	Booted   time.Time
	// The camera's LAN address and MAC, and the Wi-Fi it is set up for.
	// See Identify.
	IP, MAC           string
	WifiSSID, WifiPSK string
	// Files are added to the image as is, mode 0600, e.g. the SSH host
	// keys in dropbear's format.
	Files map[string][]byte
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
	"/etc/init.d/rcS":         {0o755, "root"},
	"/mnt/mtd/Config/shadow":  {0o600, "root"},
	"/mnt/mtd/Config/Account": {0o600, "root"},
	"/root":                   {0o700, "root"},
	"/tmp":                    {0o1777, "root"},
	"/var/tmp":                {0o1777, "root"},
}

type device struct {
	kind         vfs.Device
	block        bool
	major, minor int
	mode         fs.FileMode
}

// devices are the nodes in /dev.
var devices = map[string]device{
	"/dev/null":      {vfs.DevNull, false, 1, 3, 0o666},
	"/dev/zero":      {vfs.DevZero, false, 1, 5, 0o666},
	"/dev/random":    {vfs.DevRandom, false, 1, 8, 0o666},
	"/dev/urandom":   {vfs.DevRandom, false, 1, 9, 0o666},
	"/dev/tty":       {vfs.DevOther, false, 5, 0, 0o666},
	"/dev/console":   {vfs.DevOther, false, 5, 1, 0o600},
	"/dev/ptmx":      {vfs.DevOther, false, 5, 2, 0o666},
	"/dev/ttyAMA0":   {vfs.DevOther, false, 204, 64, 0o660},
	"/dev/watchdog":  {vfs.DevOther, false, 10, 130, 0o600},
	"/dev/mtd0":      {vfs.DevOther, false, 90, 0, 0o600},
	"/dev/mtd1":      {vfs.DevOther, false, 90, 2, 0o600},
	"/dev/mtd2":      {vfs.DevOther, false, 90, 4, 0o600},
	"/dev/mtd3":      {vfs.DevOther, false, 90, 6, 0o600},
	"/dev/mtd4":      {vfs.DevOther, false, 90, 8, 0o600},
	"/dev/mtdblock0": {vfs.DevOther, true, 31, 0, 0o600},
	"/dev/mtdblock1": {vfs.DevOther, true, 31, 1, 0o600},
	"/dev/mtdblock2": {vfs.DevOther, true, 31, 2, 0o600},
	"/dev/mtdblock3": {vfs.DevOther, true, 31, 3, 0o600},
	"/dev/mtdblock4": {vfs.DevOther, true, 31, 4, 0o600},
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
	"/bin", "/sbin", "/etc/dropbear", "/usr/bin", "/usr/sbin", "/lib", "/usr/lib", "/sys",
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

// binaryStrings is text found in the programs, for grep and friends.
var binaryStrings = map[string][]string{
	"/usr/sbin/dropbear":       {"SSH-2.0-dropbear_2019.78", "Dropbear SSH server v2019.78", "/etc/dropbear/dropbear_ecdsa_host_key"},
	"/app/ipcam":               {"IPCAM_Main", "/mnt/mtd/Config/Account", "rtsp://%s:554/user=%s&password=%s&channel=1&stream=0.sdp", "ONVIF"},
	"/lib/libuClibc-1.0.31.so": {"uClibc 1.0.31"},
}

// Build returns a fresh filesystem for host. Sessions should Clone it.
func Build(h Host) (*vfs.FS, error) {
	f := vfs.New()
	mtime := Built
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
		n.Strings = binaryStrings[p]
		n.ModTime = mtime
		f.Put(p, n)
	}
	for p, data := range h.Files {
		f.Put(p, &vfs.Node{Mode: 0o600, Owner: "root", Group: "root", ModTime: mtime, Data: data})
	}
	// The RAM filesystems were filled at boot by rcS, and the config on
	// flash was last saved when the camera was set up.
	installed := h.Booted.Add(-173*24*time.Hour - 5*time.Hour).Truncate(time.Second)
	for _, m := range []struct {
		root string
		t    time.Time
	}{
		{"/dev", h.Booted.Add(2 * time.Second)},
		{"/tmp", h.Booted.Add(2 * time.Second)},
		{"/var", h.Booted.Add(3 * time.Second)},
		{"/mnt/mtd", installed},
	} {
		_ = f.Walk(m.root, func(p string, n *vfs.Node) {
			if !n.IsDevice() {
				n.ModTime = m.t
			}
		})
	}
	for p, d := range devices {
		mode := fs.ModeDevice | d.mode
		if !d.block {
			mode |= fs.ModeCharDevice
		}
		f.Put(p, &vfs.Node{Mode: mode, Owner: "root", Group: "root", ModTime: h.Booted, Device: d.kind, Major: d.major, Minor: d.minor})
	}
	// /proc is made by the kernel at boot: no sizes, boot-time dates.
	_ = f.Walk("/proc", func(p string, n *vfs.Node) {
		n.Virtual = true
		n.ModTime = h.Booted
		if n.IsDir() {
			n.Mode = fs.ModeDir | 0o555
		} else if p != "/proc/sys/kernel/hostname" {
			n.Mode = 0o444
		}
	})
	// A little of /sys, made by the kernel at boot like /proc.
	sysfs := map[string]string{
		"/sys/class/net/eth0/address":   strings.ToLower(h.MAC) + "\n",
		"/sys/class/net/eth0/operstate": "up\n",
		"/sys/class/net/eth0/mtu":       "1500\n",
		"/sys/class/net/eth0/speed":     "100\n",
		"/sys/class/net/lo/address":     "00:00:00:00:00:00\n",
		"/sys/class/net/lo/operstate":   "unknown\n",
		"/sys/class/net/lo/mtu":         "65536\n",
		"/sys/kernel/hostname":          h.Hostname + "\n",
	}
	for p, data := range sysfs {
		f.Put(p, &vfs.Node{Mode: 0o444, Owner: "root", Group: "root", ModTime: h.Booted, Data: []byte(data), Virtual: true})
	}
	for _, d := range []string{"/sys/block", "/sys/bus", "/sys/dev", "/sys/devices", "/sys/firmware", "/sys/fs", "/sys/module", "/sys/power"} {
		f.Put(d, &vfs.Node{Mode: fs.ModeDir | 0o755, Owner: "root", Group: "root", ModTime: h.Booted, Virtual: true})
	}
	_ = f.Walk("/sys", func(_ string, n *vfs.Node) {
		n.Virtual, n.ModTime = true, h.Booted
	})
	// Pid files of the daemons rcS started.
	for p, pid := range map[string]int{"/var/run/syslogd.pid": 121, "/var/run/dropbear.pid": 124} {
		f.Put(p, &vfs.Node{Mode: 0o644, Owner: "root", Group: "root", ModTime: h.Booted.Add(6 * time.Second), Data: []byte(fmt.Sprintf("%d\n", pid))})
	}
	UpdateProc(f, System{Now: h.Booted, Booted: h.Booted, Procs: Processes, LastPID: 214, Self: 1})
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

// SetPassword stores hash as user's password in /etc/shadow, which is on
// flash and so writable. The last-changed field becomes the day of now,
// unless now is zero.
func SetPassword(f *vfs.FS, user, hash string, now time.Time) error {
	data, err := f.ReadFile("root", "/etc/shadow")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	for i, l := range lines {
		p := strings.Split(l, ":")
		if len(p) > 2 && p[0] == user {
			p[1] = hash
			if !now.IsZero() {
				p[2] = fmt.Sprint(now.Unix() / 86400)
			}
			lines[i] = strings.Join(p, ":")
		}
	}
	return f.WriteFile("root", "/etc/shadow", []byte(strings.Join(lines, "\n")+"\n"), false)
}

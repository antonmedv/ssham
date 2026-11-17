package server

import (
	"encoding/gob"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/antonmedv/ssham/internal/commands"
	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/shell"
	"github.com/antonmedv/ssham/internal/vfs"
)

// device is the camera every session logs in to: one disk and one
// process table, so a file one attacker drops is there for the next, and
// ps shows everyone. Files live until the camera reboots; files on flash
// (/mnt/mtd) survive that too. With a state file, all of it also survives
// restarts of ssham, and the uptime keeps counting.
type device struct {
	mu        sync.Mutex
	host      rootfs.Host
	fs        *vfs.FS
	kernel    *rootfs.Kernel
	downUntil time.Time
	downtime  time.Duration
	hangups   map[int]func() // open sessions, by an id
	nextID    int
	statePath string
	passwords map[string]password // the password each account has now
}

// password is an account's password, until a day after it was first used.
// See checkPassword.
type password struct {
	Value string
	Until time.Time
}

// passwordLife is how long the first default password that worked stays
// the only one that works.
const passwordLife = 24 * time.Hour

// checkPassword reports whether pw is user's password. A real camera has
// exactly one password per account, but which factory default it is
// varies by vendor. So the first common default that a bot tries becomes
// the account's password, and for a day only that one works: an attacker
// who checks whether two different passwords both work sees one fail.
func (d *device) checkPassword(user, pw string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.passwords[user]; ok && now.Before(p.Until) {
		return p.Value == pw
	}
	d.passwords[user] = password{Value: pw, Until: now.Add(passwordLife)}
	return true
}

// The RAM filesystems and flash, saved in the state file.
var persisted = []string{"/tmp", "/var", "/mnt/mtd"}

// maxDiskBytes is what all sessions together may store. When it is nearly
// full, the camera runs out of memory and its watchdog reboots it.
const maxDiskBytes = 32 << 20

type savedState struct {
	Booted    time.Time
	LastPID   int
	Trees     map[string]*vfs.Node
	Passwords map[string]password
}

func newDevice(host rootfs.Host, statePath string, downtime time.Duration) (*device, error) {
	d := &device{host: host, hangups: map[int]func(){}, statePath: statePath, downtime: downtime, passwords: map[string]password{}}
	saved, err := d.load()
	if err != nil {
		return nil, err
	}
	if saved != nil {
		d.host.Booted = saved.Booted
		for u, p := range saved.Passwords {
			d.passwords[u] = p
		}
	}
	if err := d.boot(saved); err != nil {
		return nil, err
	}
	return d, nil
}

// boot builds the disk and kernel of a camera that booted at d.host.Booted,
// with the trees in saved, if any.
func (d *device) boot(saved *savedState) error {
	f, err := rootfs.Build(d.host)
	if err != nil {
		return err
	}
	shell.Install(f, commands.Registry())
	f.MaxBytes = maxDiskBytes
	if saved != nil {
		for p, n := range saved.Trees {
			f.Delete(p) // replace the fresh tree, not merge into it
			f.Put(p, n)
		}
	}
	d.fs = f
	d.kernel = rootfs.NewKernel(d.host.Booted, time.Now())
	if saved != nil && saved.LastPID > 0 {
		d.kernel = rootfs.NewKernelAt(d.host.Booted, saved.LastPID)
	}
	return nil
}

// disk is the camera's filesystem.
func (d *device) disk() *vfs.FS {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fs
}

// session registers a new session; hangup ends it. It returns the state
// the session runs on, and a function to call when it ends.
func (d *device) session(hangup func()) (rootfs.Host, *vfs.FS, *rootfs.Kernel, func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.nextID
	d.nextID++
	d.hangups[id] = hangup
	return d.host, d.fs, d.kernel, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		delete(d.hangups, id)
	}
}

// up reports whether the camera accepts connections. A camera whose
// memory is nearly full is rebooted by its watchdog first.
func (d *device) up(now time.Time) bool {
	d.mu.Lock()
	down := now.Before(d.downUntil)
	full := false
	if !down {
		used, _ := d.fs.Used()
		full = used > maxDiskBytes*9/10
	}
	d.mu.Unlock()
	if full {
		d.reboot(now)
		return false
	}
	return !down
}

// reboot takes the camera down: every session is cut, the RAM
// filesystems are emptied, and it is back after the downtime with a new
// boot time and fresh pids. The flash keeps its files.
func (d *device) reboot(now time.Time) {
	d.mu.Lock()
	hangups := d.hangups
	d.hangups = map[int]func(){}
	flash, _ := d.fs.Export("/mnt/mtd")
	d.downUntil = now.Add(d.downtime)
	d.host.Booted = now.Add(d.downtime * 9 / 10)
	var saved *savedState
	if flash != nil {
		saved = &savedState{Trees: map[string]*vfs.Node{"/mnt/mtd": flash}}
	}
	_ = d.boot(saved)
	d.kernel = rootfs.NewKernelAt(d.host.Booted, 254)
	d.mu.Unlock()
	for _, h := range hangups {
		h()
	}
}

func (d *device) load() (*savedState, error) {
	if d.statePath == "" {
		return nil, nil
	}
	f, err := os.Open(d.statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s savedState
	if err := gob.NewDecoder(f).Decode(&s); err != nil {
		// A broken state file is not worth refusing to start for.
		return nil, nil
	}
	return &s, nil
}

// save writes the state file, atomically.
func (d *device) save() error {
	if d.statePath == "" {
		return nil
	}
	d.mu.Lock()
	s := savedState{Booted: d.host.Booted, LastPID: d.kernel.LastPID(), Trees: map[string]*vfs.Node{}, Passwords: d.passwords}
	for _, p := range persisted {
		if n, err := d.fs.Export(p); err == nil {
			s.Trees[p] = n
		}
	}
	d.mu.Unlock()
	tmp, err := os.CreateTemp(filepath.Dir(d.statePath), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := gob.NewEncoder(tmp).Encode(&s); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), d.statePath)
}

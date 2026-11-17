package rootfs

import (
	"slices"
	"sync"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

// Kernel is the running system that every session on the camera shares:
// the process table, pid numbering and the terminals. Sessions see each
// other in ps, and pids only go up, as on a real device.
type Kernel struct {
	mu      sync.Mutex
	booted  time.Time
	lastPID int
	procs   map[int]Proc // processes sessions started
	killed  map[int]bool // the camera's own processes someone killed
	pts     map[int]bool // terminals in use
	// handlers deliver signals to processes that are sessions: their
	// shell and dropbear.
	handlers map[int]func(sig int)
}

const pidMax = 32768

// NewKernel returns the kernel of a camera that booted at booted and has
// been running until now: pids have advanced as they do on a camera that
// runs a few jobs a minute.
func NewKernel(booted, now time.Time) *Kernel {
	up := max(now.Sub(booted), 0)
	last := 300 + int(up.Seconds()/23)%(pidMax-400)
	return &Kernel{booted: booted, lastPID: last, procs: map[int]Proc{}, killed: map[int]bool{}, pts: map[int]bool{}, handlers: map[int]func(int){}}
}

// NewKernelAt returns the kernel of a camera that booted at booted and
// whose most recent pid is lastPID.
func NewKernelAt(booted time.Time, lastPID int) *Kernel {
	k := NewKernel(booted, booted)
	k.lastPID = lastPID
	return k
}

// Booted is when the camera last booted.
func (k *Kernel) Booted() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.booted
}

// AllocPID returns the next free pid. Other activity on the camera (the
// ipcam threads come and go) uses some too.
func (k *Kernel) AllocPID(skip int) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	for {
		k.lastPID += 1 + skip
		skip = 0
		if k.lastPID >= pidMax {
			k.lastPID = 300
		}
		if _, used := k.procs[k.lastPID]; !used && !isBootPID(k.lastPID) {
			return k.lastPID
		}
	}
}

// LastPID is the most recent pid, as /proc/loadavg shows it.
func (k *Kernel) LastPID() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lastPID
}

func isBootPID(pid int) bool {
	for _, p := range Processes {
		if p.PID == pid {
			return true
		}
	}
	return false
}

// Add puts p in the process table, replacing any process with its pid.
func (k *Kernel) Add(p Proc) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.procs[p.PID] = p
}

// Remove takes pid out of the process table.
func (k *Kernel) Remove(pid int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.procs, pid)
	delete(k.handlers, pid)
}

// Handle makes signals to pid call fn.
func (k *Kernel) Handle(pid int, fn func(sig int)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.handlers[pid] = fn
}

// Signal sends sig to pid, as kill does. It reports whether there was
// such a process. Signal 0 only checks. init and kernel threads ignore
// signals; the camera's daemons die; a session's shell or dropbear get
// the signal through their handler.
func (k *Kernel) Signal(pid, sig int, now time.Time) bool {
	if !k.Alive(pid, now) {
		return false
	}
	if sig == 0 {
		return true
	}
	k.mu.Lock()
	fn := k.handlers[pid]
	_, started := k.procs[pid]
	k.mu.Unlock()
	switch {
	case fn != nil:
		fn(sig)
	case started:
		k.Remove(pid)
	case pid != 1 && !isKernelThread(pid):
		k.KillBoot(pid)
	}
	return true
}

func isKernelThread(pid int) bool {
	for _, p := range Processes {
		if p.PID == pid {
			return p.Kernel()
		}
	}
	return false
}

// Get returns a process sessions started.
func (k *Kernel) Get(pid int) (Proc, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	p, ok := k.procs[pid]
	return p, ok
}

// KillBoot kills one of the camera's own processes, which then no longer
// shows in ps. It reports whether there was such a process alive.
func (k *Kernel) KillBoot(pid int) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !isBootPID(pid) || k.killed[pid] {
		return false
	}
	k.killed[pid] = true
	return true
}

// Alive reports whether pid is a running process.
func (k *Kernel) Alive(pid int, now time.Time) bool {
	for _, p := range k.Procs(now) {
		if p.PID == pid {
			return true
		}
	}
	return false
}

// Procs returns every running process at now.
func (k *Kernel) Procs(now time.Time) []Proc {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []Proc
	for _, p := range Processes {
		if !k.killed[p.PID] {
			out = append(out, p)
		}
	}
	for pid, p := range k.procs {
		if !p.Until.IsZero() && !now.Before(p.Until) {
			delete(k.procs, pid) // a background job that has finished
			continue
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Proc) int { return a.PID - b.PID })
	return out
}

// Sync makes /proc on f show the processes at now, as seen by self.
func (k *Kernel) Sync(f *vfs.FS, now time.Time, self int) {
	procs := k.Procs(now)
	k.mu.Lock()
	defer k.mu.Unlock()
	UpdateProc(f, System{Now: now, Booted: k.booted, Procs: procs, LastPID: k.lastPID, Self: self})
}

// OpenPTY returns the lowest free terminal number, for /dev/pts/N.
func (k *Kernel) OpenPTY() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for k.pts[n] {
		n++
	}
	k.pts[n] = true
	return n
}

// ClosePTY frees terminal n.
func (k *Kernel) ClosePTY(n int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.pts, n)
}

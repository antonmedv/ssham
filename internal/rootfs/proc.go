package rootfs

import (
	"fmt"
	"io/fs"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

// Proc is a process, as /proc shows it.
type Proc struct {
	PID, PPID int
	Comm      string   // the kernel's short name, e.g. "ipcam"
	Cmdline   []string // argv; empty for kernel threads
	Exe       string   // the program file; empty for kernel threads
	State     byte     // 'S' sleeping, 'R' running
	VSZ       int      // kB
	RSS       int      // kB
	Threads   int
	Started   time.Duration // after boot
	HighPrio  bool          // a kernel worker with nice -20
	// Until is when a background job ends and leaves the process table;
	// zero means until it is removed.
	Until time.Time
	// TTY is the terminal its stdin, stdout and stderr are open on, if
	// any; Environ its environment.
	TTY     string
	Environ []string
}

// Kernel reports whether p is a kernel thread.
func (p Proc) Kernel() bool { return len(p.Cmdline) == 0 }

// Processes are what runs on the camera on its own, in boot order: see
// /etc/init.d/rcS and /etc/inittab.
var Processes = []Proc{
	{PID: 1, Comm: "init", Cmdline: []string{"init"}, Exe: "/bin/busybox", VSZ: 1240, RSS: 588, Threads: 1},
	kthread(2, "kthreadd", false),
	kthread(3, "ksoftirqd/0", false),
	kthread(5, "kworker/0:0H", true),
	kthread(7, "rcu_sched", false),
	kthread(8, "rcu_bh", false),
	kthread(9, "lru-add-drain", true),
	kthread(10, "kdevtmpfs", false),
	kthread(11, "netns", true),
	kthread(12, "oom_reaper", false),
	kthread(13, "writeback", true),
	kthread(14, "crypto", true),
	kthread(15, "bioset", true),
	kthread(16, "kblockd", true),
	kthread(17, "watchdogd", false),
	kthread(19, "rpciod", true),
	kthread(38, "kswapd0", false),
	kthread(39, "vmstat", true),
	kthread(77, "mtdblock0", false),
	kthread(78, "mtdblock1", false),
	kthread(79, "mtdblock2", false),
	kthread(80, "mtdblock3", false),
	kthread(81, "mtdblock4", false),
	kthread(97, "jffs2_gcd_mtd4", false),
	{PID: 121, PPID: 1, Comm: "syslogd", Cmdline: []string{"/sbin/syslogd", "-C64"}, Exe: "/bin/busybox", VSZ: 1236, RSS: 432, Threads: 1, Started: 6 * time.Second},
	{PID: 124, PPID: 1, Comm: "dropbear", Cmdline: []string{"/usr/sbin/dropbear", "-R", "-p", "22"}, Exe: "/usr/sbin/dropbear", VSZ: 1052, RSS: 412, Threads: 1, Started: 6 * time.Second},
	{PID: 126, PPID: 1, Comm: "ipcam", Cmdline: []string{"./ipcam"}, Exe: "/app/ipcam", VSZ: 38472, RSS: 11840, Threads: 38, Started: 7 * time.Second},
	{PID: 127, PPID: 1, Comm: "getty", Cmdline: []string{"/sbin/getty", "-L", "ttyAMA0", "115200", "vt100"}, Exe: "/bin/busybox", VSZ: 1236, RSS: 380, Threads: 1, Started: 7 * time.Second},
	kthread(214, "kworker/0:1", false),
}

func kthread(pid int, comm string, high bool) Proc {
	ppid := 2
	if pid == 2 {
		ppid = 0
	}
	return Proc{PID: pid, PPID: ppid, Comm: comm, Threads: 1, HighPrio: high}
}

// System is the state /proc is made from.
type System struct {
	Now     time.Time
	Booted  time.Time
	Procs   []Proc // all of them, Processes included
	LastPID int
	Self    int // the process reading /proc
}

// LoadAvg returns the 1, 5 and 15 minute load averages at t: a camera
// encoding video all day sits a little under 0.5, drifting slowly.
func LoadAvg(t time.Time) [3]float64 {
	x := float64(t.Unix())
	wave := func(period, phase float64) float64 { return math.Sin(x/period + phase) }
	l15 := 0.45 + 0.06*wave(5400, 0.3)
	l5 := l15 + 0.05*wave(1300, 1.1)
	l1 := l5 + 0.09*wave(170, 2.0) + 0.04*wave(41, 0.5)
	return [3]float64{max(l1, 0.05), max(l5, 0.05), max(l15, 0.05)}
}

// UpdateProc makes /proc match sys. Time-dependent files are rewritten;
// process directories are added and removed as processes come and go.
func UpdateProc(f *vfs.FS, sys System) {
	up := sys.Now.Sub(sys.Booted)
	file := func(p, data string) {
		f.Put(p, &vfs.Node{Mode: 0o444, Owner: "root", Group: "root", ModTime: sys.Now, Data: []byte(data), Virtual: true})
	}

	file("/proc/uptime", fmt.Sprintf("%.2f %.2f\n", up.Seconds(), up.Seconds()*0.93))
	threads := 0
	for _, p := range sys.Procs {
		threads += max(p.Threads, 1)
	}
	l := LoadAvg(sys.Now)
	file("/proc/loadavg", fmt.Sprintf("%.2f %.2f %.2f 1/%d %d\n", l[0], l[1], l[2], threads, sys.LastPID))
	file("/proc/stat", procStat(sys, up))
	file("/proc/net/dev", procNetDev(up))

	have := map[int]bool{}
	for _, p := range sys.Procs {
		have[p.PID] = true
		dir := "/proc/" + strconv.Itoa(p.PID)
		if n, err := f.Lstat("root", dir); err == nil && n.Virtual {
			continue // already there
		}
		writeProc(f, sys, p)
	}
	if entries, err := f.ReadDir("root", "/proc"); err == nil {
		for _, e := range entries {
			if pid, err := strconv.Atoi(e.Name); err == nil && !have[pid] {
				f.Delete("/proc/" + e.Name)
			}
		}
	}
	// procfs makes its inodes when they are looked up: they look new.
	if entries, err := f.ReadDir("root", "/proc"); err == nil {
		for _, e := range entries {
			if _, err := strconv.Atoi(e.Name); err != nil && e.Name != "sys" {
				_ = f.Walk("/proc/"+e.Name, func(_ string, n *vfs.Node) { n.ModTime = sys.Now })
			}
		}
	}
	f.Put("/proc/self", &vfs.Node{Mode: fs.ModeSymlink | 0o777, Owner: "root", Group: "root", ModTime: sys.Booted, Target: strconv.Itoa(sys.Self), Virtual: true})
}

func procStat(sys System, up time.Duration) string {
	j := int64(up.Seconds() * 100) // jiffies
	user, system, irq, softirq := j*3/100, j*2/100, j/400, j/200
	idle := j - user - system - irq - softirq
	cpu := fmt.Sprintf("%d 0 %d %d 0 %d %d 0 0 0", user, system, idle, irq, softirq)
	return fmt.Sprintf("cpu  %s\ncpu0 %s\nintr %d\nctxt %d\nbtime %d\nprocesses %d\nprocs_running 1\nprocs_blocked 0\nsoftirq %d\n",
		cpu, cpu, j*21, j*96, sys.Booted.Unix(), sys.LastPID, j*7)
}

func writeProc(f *vfs.FS, sys System, p Proc) {
	dir := "/proc/" + strconv.Itoa(p.PID)
	start := sys.Booted.Add(p.Started)
	f.Put(dir, &vfs.Node{Mode: fs.ModeDir | 0o555, Owner: "root", Group: "root", ModTime: start, Virtual: true})
	file := func(name string, mode fs.FileMode, data string) {
		f.Put(dir+"/"+name, &vfs.Node{Mode: mode, Owner: "root", Group: "root", ModTime: start, Data: []byte(data), Virtual: true})
	}
	cmdline := ""
	if len(p.Cmdline) > 0 {
		cmdline = strings.Join(p.Cmdline, "\x00") + "\x00"
	}
	file("cmdline", 0o444, cmdline)
	file("comm", 0o644, p.Comm+"\n")
	file("stat", 0o444, statLine(p))
	file("status", 0o444, statusFile(p))
	link := func(name, target string) {
		f.Put(dir+"/"+name, &vfs.Node{Mode: fs.ModeSymlink | 0o777, Owner: "root", Group: "root", ModTime: start, Target: target, Virtual: true})
	}
	f.Put(dir+"/fd", &vfs.Node{Mode: fs.ModeDir | 0o500, Owner: "root", Group: "root", ModTime: start, Virtual: true})
	f.Put(dir+"/task", &vfs.Node{Mode: fs.ModeDir | 0o555, Owner: "root", Group: "root", ModTime: start, Virtual: true})
	task := dir + "/task/" + strconv.Itoa(p.PID)
	f.Put(task, &vfs.Node{Mode: fs.ModeDir | 0o555, Owner: "root", Group: "root", ModTime: start, Virtual: true})
	for _, name := range []string{"comm", "stat", "status"} {
		n, _ := f.Lstat("root", dir+"/"+name)
		f.Put(task+"/"+name, &vfs.Node{Mode: n.Mode, Owner: "root", Group: "root", ModTime: start, Data: n.Data, Virtual: true})
	}
	link("root", "/")
	if p.Kernel() {
		file("environ", 0o400, "")
		file("maps", 0o444, "")
		return
	}
	link("exe", p.Exe)
	link("cwd", cwdOf(p))
	env := p.Environ
	if env == nil {
		env = []string{"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin"}
	}
	file("environ", 0o400, strings.Join(env, "\x00")+"\x00")
	file("maps", 0o444, procMaps(p))
	stdio := p.TTY
	if stdio == "" {
		stdio = "/dev/null"
	}
	for i := 0; i < 3; i++ {
		link("fd/"+strconv.Itoa(i), stdio)
	}
	if p.Comm == "ipcam" || p.Comm == "dropbear" {
		for i := 3; i < 7; i++ {
			link("fd/"+strconv.Itoa(i), fmt.Sprintf("socket:[%d]", 2000+p.PID*7+i))
		}
	}
}

// procMaps is a plausible memory map: the program, uClibc, heap and stack.
func procMaps(p Proc) string {
	exe := p.Exe
	var b strings.Builder
	line := func(lo, hi uint32, perm string, off uint32, dev string, ino int, name string) {
		fmt.Fprintf(&b, "%08x-%08x %s %08x %s %-10d", lo, hi, perm, off, dev, ino)
		if name != "" {
			b.WriteString("     " + name)
		}
		b.WriteByte('\n')
	}
	text := uint32(0x10000 + (p.VSZ%7)*0x1000)
	end := text + 0xe8000
	if exe == "/app/ipcam" {
		end = text + 0x1b0000
	}
	line(0x10000, end, "r-xp", 0, "1f:03", 211, exe)
	line(end+0xf000, end+0x10000, "rw-p", end-0x10000, "1f:03", 211, exe)
	line(end+0x10000, end+0x31000, "rw-p", 0, "00:00", 0, "[heap]")
	base := uint32(0xb6e00000 + (p.PID%64)*0x1000)
	line(base, base+0x5d000, "r-xp", 0, "1f:03", 412, "/lib/libuClibc-1.0.31.so")
	line(base+0x6c000, base+0x6d000, "r--p", 0x5c000, "1f:03", 412, "/lib/libuClibc-1.0.31.so")
	line(base+0x6d000, base+0x6e000, "rw-p", 0x5d000, "1f:03", 412, "/lib/libuClibc-1.0.31.so")
	line(base+0x80000, base+0x87000, "r-xp", 0, "1f:03", 409, "/lib/ld-uClibc-1.0.31.so")
	stack := uint32(0xbef00000 + (p.PID%200)*0x1000)
	line(stack, stack+0x21000, "rw-p", 0, "00:00", 0, "[stack]")
	line(0xffff0000, 0xffff1000, "r-xp", 0, "00:00", 0, "[vectors]")
	return b.String()
}

func cwdOf(p Proc) string {
	if p.Comm == "ipcam" {
		return "/app"
	}
	return "/"
}

func statLine(p Proc) string {
	state := p.State
	if state == 0 {
		state = 'S'
	}
	prio, nice := 20, 0
	if p.HighPrio {
		prio, nice = 0, -20
	}
	flags := 0x400100 // PF_SUPERPRIV | PF_RANDOMIZE
	if p.Kernel() {
		flags = 0x208040 // PF_KTHREAD | PF_NOFREEZE | PF_FORKNOEXEC
	}
	start := int64(p.Started.Seconds() * 100)
	return fmt.Sprintf("%d (%s) %c %d %d %d 0 -1 %d 0 0 0 0 0 0 0 0 %d %d %d 0 %d %d %d 4294967295 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
		p.PID, p.Comm, state, p.PPID, p.PID, p.PID, flags, prio, nice, max(p.Threads, 1), start, p.VSZ*1024, p.RSS/4)
}

func statusFile(p Proc) string {
	state := "S (sleeping)"
	if p.State == 'R' {
		state = "R (running)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Name:\t%s\nUmask:\t0022\nState:\t%s\nTgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t%d\nTracerPid:\t0\n", p.Comm, state, p.PID, p.PID, p.PPID)
	b.WriteString("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t32\nGroups:\t\n")
	if !p.Kernel() {
		fmt.Fprintf(&b, "VmPeak:\t%8d kB\nVmSize:\t%8d kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t%8d kB\nVmRSS:\t%8d kB\n", p.VSZ, p.VSZ, p.RSS, p.RSS)
		fmt.Fprintf(&b, "RssAnon:\t%8d kB\nRssFile:\t%8d kB\nRssShmem:\t       0 kB\n", p.RSS/3, p.RSS-p.RSS/3)
		fmt.Fprintf(&b, "VmData:\t%8d kB\nVmStk:\t     132 kB\nVmExe:\t%8d kB\nVmLib:\t    1452 kB\nVmPTE:\t      12 kB\nVmPMD:\t       0 kB\nVmSwap:\t       0 kB\n", p.VSZ/4, min(p.VSZ/3, 980))
	}
	fmt.Fprintf(&b, "Threads:\t%d\nSigQ:\t0/471\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n", max(p.Threads, 1))
	b.WriteString("SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\n")
	b.WriteString("CapInh:\t0000000000000000\nCapPrm:\t0000003fffffffff\nCapEff:\t0000003fffffffff\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\n")
	b.WriteString("Cpus_allowed:\t1\nCpus_allowed_list:\t0\nvoluntary_ctxt_switches:\t1204\nnonvoluntary_ctxt_switches:\t87\n")
	return b.String()
}

// IfStats are an interface's counters.
type IfStats struct {
	Name                       string
	RxBytes, RxPkts            uint32
	TxBytes, TxPkts, Multicast uint32
}

// NetDev returns the counters of eth0 and lo after up of uptime. The
// camera mostly sends video. The counters are 32 bits wide on this
// kernel, so they wrap.
func NetDev(up time.Duration) []IfStats {
	s := uint64(up.Seconds())
	return []IfStats{
		{Name: "eth0", RxBytes: uint32(s * 118), RxPkts: uint32(s * 118 / 136), TxBytes: uint32(s * 947), TxPkts: uint32(s * 947 / 1102), Multicast: uint32(s / 197)},
		{Name: "lo", RxBytes: uint32(s / 25), RxPkts: uint32(s / 2000), TxBytes: uint32(s / 25), TxPkts: uint32(s / 2000)},
	}
}

func procNetDev(up time.Duration) string {
	var b strings.Builder
	b.WriteString("Inter-|   Receive                                                |  Transmit\n")
	b.WriteString(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n")
	for _, i := range []IfStats{NetDev(up)[1], NetDev(up)[0]} {
		fmt.Fprintf(&b, "%6s:%8d %7d    0    0    0     0          0 %9d %8d %7d    0    0    0     0       0          0\n",
			i.Name, i.RxBytes, i.RxPkts, i.Multicast, i.TxBytes, i.TxPkts)
	}
	return b.String()
}

package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/shell"
)

// What the boot left behind: the kernel log, the system log, and the
// programs /etc/inittab and /etc/init.d/rcS start, so everything ps shows
// exists on disk.

func init() {
	register(
		shell.Command{Name: "dmesg", Usage: "[-c] [-n LEVEL] [-s SIZE]", Run: cmdDmesg},
		shell.Command{Name: "logread", Dir: "/sbin", Usage: "[-fF]", Run: cmdLogread},
		shell.Command{Name: "init", Dir: "/sbin", Usage: "", Run: cmdInit},
		shell.Command{Name: "syslogd", Dir: "/sbin", Usage: "[OPTIONS]", Run: cmdSyslogd},
		shell.Command{Name: "getty", Dir: "/sbin", Usage: "[OPTIONS] BAUD_RATE[,BAUD_RATE]... TTY [TERMTYPE]", Run: cmdGetty},
		shell.Command{Name: "umount", Usage: "[OPTIONS] FILESYSTEM|DIRECTORY", Run: cmdUmount},
		shell.Command{Name: "readlink", Dir: "/usr/bin", Usage: "[-fnv] FILE", Run: cmdReadlink},
	)
}

const dmesgText = `[    0.000000] Booting Linux on physical CPU 0x0
[    0.000000] Linux version %[1]s (builder@buildhost) (gcc version 6.3.0 (crosstool-NG 1.24.0)) #1 Fri Mar 12 10:58:47 CST 2021
[    0.000000] CPU: ARMv7 Processor [410fc075] revision 5 (ARMv7), cr=10c5387d
[    0.000000] CPU: div instructions available: patching division code
[    0.000000] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
[    0.000000] OF: fdt:Machine model: Generic DT based system
[    0.000000] Memory policy: Data cache writealloc
[    0.000000] On node 0 totalpages: 16384
[    0.000000] free_area_init_node: node 0, pgdat c05d5b40, node_mem_map c3f78000
[    0.000000]   Normal zone: 128 pages used for memmap
[    0.000000]   Normal zone: 0 pages reserved
[    0.000000]   Normal zone: 16384 pages, LIFO batch:3
[    0.000000] pcpu-alloc: s0 r0 d32768 u32768 alloc=1*32768
[    0.000000] pcpu-alloc: [0] 0
[    0.000000] Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 16256
[    0.000000] Kernel command line: %[2]s
[    0.000000] PID hash table entries: 256 (order: -2, 1024 bytes)
[    0.000000] Dentry cache hash table entries: 8192 (order: 3, 32768 bytes)
[    0.000000] Inode-cache hash table entries: 4096 (order: 2, 16384 bytes)
[    0.000000] Memory: 59060K/65536K available (3780K kernel code, 166K rwdata, 952K rodata, 160K init, 199K bss, 6476K reserved, 0K cma-reserved)
[    0.000000] NR_IRQS:16 nr_irqs:16 16
[    0.000000] arch_timer: cp15 timer(s) running at 50.00MHz (phys).
[    0.000000] clocksource: arch_sys_counter: mask: 0xffffffffffffff max_cycles: 0xb8812736b, max_idle_ns: 440795202655 ns
[    0.000006] sched_clock: 56 bits at 50MHz, resolution 20ns, wraps every 4398046511100ns
[    0.000226] Calibrating delay loop (skipped), value calculated using timer frequency.. 100.00 BogoMIPS (lpj=500000)
[    0.000251] pid_max: default: 32768 minimum: 301
[    0.000453] Mount-cache hash table entries: 1024 (order: 0, 4096 bytes)
[    0.001338] CPU: Testing write buffer coherency: ok
[    0.002186] Setting up static identity map for 0x80008200 - 0x80008260
[    0.004912] devtmpfs: initialized
[    0.011806] VFP support v0.3: implementor 41 architecture 2 part 30 variant 7 rev 5
[    0.012153] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 19112604462750000 ns
[    0.012714] NET: Registered protocol family 16
[    0.014197] DMA: preallocated 256 KiB pool for atomic coherent allocations
[    0.052843] SCSI subsystem initialized
[    0.054226] clocksource: Switched to clocksource arch_sys_counter
[    0.068102] NET: Registered protocol family 2
[    0.069348] TCP established hash table entries: 1024 (order: 0, 4096 bytes)
[    0.069456] TCP bind hash table entries: 1024 (order: 0, 4096 bytes)
[    0.069551] TCP: Hash tables configured (established 1024 bind 1024)
[    0.069879] UDP hash table entries: 256 (order: 0, 4096 bytes)
[    0.070273] NET: Registered protocol family 1
[    0.071914] squashfs: version 4.0 (2009/01/31) Phillip Lougher
[    0.072461] jffs2: version 2.2. (NAND) (SUMMARY)  © 2001-2006 Red Hat, Inc.
[    0.080356] io scheduler noop registered (default)
[    0.091207] Serial: AMBA PL011 UART driver
[    0.091865] 12040000.uart: ttyAMA0 at MMIO 0x12040000 (irq = 23, base_baud = 0) is a PL011 rev2
[    0.552918] console [ttyAMA0] enabled
[    0.563104] hisi-sfc 10000000.flash-memory: SPI Nor ID Table Version 1.0
[    0.571332] hisi-sfc 10000000.flash-memory: SPI Nor(cs 0) ID: 0xef 0x40 0x17
[    0.578659] hisi-sfc 10000000.flash-memory: Block:64KB Chip:8MB Name:"W25Q64FV"
[    0.586512] 5 cmdlinepart partitions found on MTD device sfc
[    0.592305] Creating 5 MTD partitions on "sfc":
[    0.596913] 0x000000000000-0x000000040000 : "boot"
[    0.602943] 0x000000040000-0x000000050000 : "env"
[    0.608792] 0x000000050000-0x0000001e0000 : "kernel"
[    0.614841] 0x0000001e0000-0x000000680000 : "rootfs"
[    0.620912] 0x000000680000-0x000000800000 : "config"
[    0.638451] libphy: Fixed MDIO Bus: probed
[    0.647117] hieth 10050000.ethernet: connect to PHY failed!
[    0.659883] NET: Registered protocol family 17
[    0.664611] Registering SWP/SWPB emulation handler
[    0.688903] VFS: Mounted root (squashfs filesystem) readonly on device 31:3.
[    0.701234] devtmpfs: mounted
[    0.704602] Freeing unused kernel memory: 160K
[    0.709180] This architecture does not have kernel memory protection.
[    1.927731] jffs2: notice: (97) jffs2_build_xattr_subsystem: complete building xattr subsystem.
[    3.104822] hieth: eth0: link up, 100Mbps, full-duplex, lpa 0x45E1
[    7.416270] random: crng init done
`

func cmdDmesg(e *shell.Env) int {
	cmdline, _ := e.FS.AsRoot().ReadFile("/proc/cmdline")
	e.Printf(dmesgText, e.Host().Kernel, strings.TrimSpace(string(cmdline)))
	return 0
}

// cmdLogread prints syslogd's in-memory log (syslogd -C): its start, and
// dropbear's lines about this very connection.
func cmdLogread(e *shell.Env) int {
	h, sess := e.Host(), e.Session()
	at := func(t time.Time) string { return t.In(zone).Format("Jan _2 15:04:05") }
	boot := h.Booted
	e.Printf("%s %s syslog.info syslogd started: %s\n", at(boot.Add(6*time.Second)), h.Hostname, "BusyBox v1.31.1")
	e.Printf("%s %s authpriv.info dropbear[124]: Running in background\n", at(boot.Add(6*time.Second)), h.Hostname)
	addr := fmt.Sprintf("%s:%d", sess.ClientIP, sess.ClientPort)
	pid := sess.PID - 1
	login := sess.Started.Add(-300 * time.Millisecond)
	e.Printf("%s %s authpriv.info dropbear[%d]: Child connection from %s\n", at(login), h.Hostname, pid, addr)
	e.Printf("%s %s authpriv.notice dropbear[%d]: Password auth succeeded for '%s' from %s\n", at(sess.Started), h.Hostname, pid, sess.LoginUser, addr)
	return 0
}

func cmdInit(e *shell.Env) int {
	e.Errorf("must be run as PID 1")
	return 1
}

// cmdSyslogd starts another syslogd, which goes to the background.
func cmdSyslogd(e *shell.Env) int { return 0 }

func cmdGetty(e *shell.Env) int {
	if len(e.Flags("I", "H", "f", "l", "t").Args) < 2 {
		return e.Usage()
	}
	e.Errorf("setsid: Operation not permitted")
	return 1
}

func cmdUmount(e *shell.Env) int {
	o := e.Flags("t", "O")
	if len(o.Args) == 0 && !o.Has("a") {
		return e.Usage()
	}
	mounts, _ := e.FS.AsRoot().ReadFile("/proc/mounts")
	status := 0
	for _, t := range o.Args {
		p := e.FS.Abs(t)
		mounted := false
		for _, l := range splitLines(string(mounts)) {
			if f := strings.Fields(l); len(f) > 1 && (f[1] == p || f[0] == t) {
				mounted = true
			}
		}
		reason := "Invalid argument"
		if mounted {
			reason = "Device or resource busy"
		}
		e.Errorf("can't unmount %s: %s", t, reason)
		status = 1
	}
	return status
}

func cmdReadlink(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) != 1 {
		return e.Usage()
	}
	name := o.Args[0]
	if o.Has("f") {
		p, err := e.FS.Realpath(name)
		if err != nil {
			return 1
		}
		e.Printf("%s\n", p)
		return 0
	}
	n, err := e.FS.Lstat(name)
	if err != nil || !n.IsLink() {
		if o.Has("v") && err != nil {
			e.Errorf("%s: %s", name, err)
		}
		return 1
	}
	e.Print(n.Target)
	if !o.Has("n") {
		e.Print("\n")
	}
	return 0
}

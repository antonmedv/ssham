package commands

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "uname", Run: cmdUname},
		shell.Command{Name: "hostname", Run: cmdHostname},
		shell.Command{Name: "uptime", Run: cmdUptime},
		shell.Command{Name: "w", Aliases: []string{"who"}, Run: cmdW},
		shell.Command{Name: "last", Run: cmdLast},
		shell.Command{Name: "free", Run: cmdFree},
		shell.Command{Name: "df", Run: cmdDf},
		shell.Command{Name: "nproc", Run: cmdNproc},
		shell.Command{Name: "lscpu", Run: cmdLscpu},
		shell.Command{Name: "lsb_release", Run: cmdLsbRelease},
		shell.Command{Name: "hostnamectl", Run: cmdHostnamectl},
		shell.Command{Name: "dmesg", Run: cmdDmesg},
		shell.Command{Name: "lsblk", Run: cmdLsblk},
		shell.Command{Name: "mount", Run: cmdMount},
		shell.Command{Name: "date", Run: cmdDate},
	)
}

func cmdUname(e *shell.Env) int {
	h := e.Host()
	o := e.Flags()
	ver := "#48-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 27 14:04:52 UTC 2024"
	fields := []struct {
		flags []string
		val   string
	}{
		{[]string{"s", "kernel-name"}, "Linux"},
		{[]string{"n", "nodename"}, h.Hostname},
		{[]string{"r", "kernel-release"}, h.Kernel},
		{[]string{"v", "kernel-version"}, ver},
		{[]string{"m", "machine"}, "x86_64"},
		{[]string{"p", "processor"}, "x86_64"},
		{[]string{"i", "hardware-platform"}, "x86_64"},
		{[]string{"o", "operating-system"}, "GNU/Linux"},
	}
	var out []string
	all := o.Has("a", "all")
	for i, f := range fields {
		if all && (i == 5 || i == 6) {
			continue
		}
		if all || o.Has(f.flags...) {
			out = append(out, f.val)
		}
	}
	if len(out) == 0 {
		out = []string{"Linux"}
	}
	e.Printf("%s\n", strings.Join(out, " "))
	return 0
}

func cmdHostname(e *shell.Env) int {
	h := e.Host().Hostname
	if len(e.Args) > 1 {
		switch e.Args[1] {
		case "-I", "--all-ip-addresses":
			e.Print("10.0.2.15 172.17.0.1 \n")
			return 0
		case "-i", "--ip-address":
			e.Print("127.0.1.1\n")
			return 0
		case "-f", "--fqdn", "--long":
			e.Printf("%s\n", h)
			return 0
		case "-s", "--short":
			e.Printf("%s\n", strings.SplitN(h, ".", 2)[0])
			return 0
		}
		if !strings.HasPrefix(e.Args[1], "-") {
			if !e.User().IsRoot() {
				fmt.Fprintln(e.Stderr, "hostname: you must be root to change the host name")
				return 1
			}
			return 0
		}
	}
	e.Printf("%s\n", h)
	return 0
}

func cmdUptime(e *shell.Env) int {
	up := e.Now().Sub(e.Host().Booted)
	if len(e.Args) > 1 && (e.Args[1] == "-p" || e.Args[1] == "--pretty") {
		days := int(up.Hours()) / 24
		e.Printf("up %d weeks, %d days, %d hours, %d minutes\n", days/7, days%7, int(up.Hours())%24, int(up.Minutes())%60)
		return 0
	}
	if len(e.Args) > 1 && (e.Args[1] == "-s" || e.Args[1] == "--since") {
		e.Printf("%s\n", e.Host().Booted.Format("2006-01-02 15:04:05"))
		return 0
	}
	e.Printf(" %s up %s,  1 user,  load average: 0.08, 0.03, 0.01\n", e.Now().Format("15:04:05"), uptimeString(up))
	return 0
}

func uptimeString(d time.Duration) string {
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	out := ""
	if days > 0 {
		out = fmt.Sprintf("%d days, ", days)
	}
	if h > 0 {
		return out + fmt.Sprintf("%2d:%02d", h, m)
	}
	return out + fmt.Sprintf("%d min", m)
}

func cmdW(e *shell.Env) int {
	up := e.Now().Sub(e.Host().Booted)
	if e.Args[0] == "w" {
		e.Printf(" %s up %s,  1 user,  load average: 0.08, 0.03, 0.01\n", e.Now().Format("15:04:05"), uptimeString(up))
		e.Print("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n")
		e.Printf("%-8s pts/0    %-16s %s    0.00s  0.02s  0.00s w\n", e.Session().LoginUser, e.Session().ClientIP, e.Session().Started.Format("15:04"))
		return 0
	}
	e.Printf("%-8s pts/0        %s (%s)\n", e.Session().LoginUser, e.Session().Started.Format("2006-01-02 15:04"), e.Session().ClientIP)
	return 0
}

func cmdLast(e *shell.Env) int {
	e.Printf("%-8s pts/0        %-16s %s   still logged in\n", e.Session().LoginUser, e.Session().ClientIP, e.Session().Started.Format("Mon Jan _2 15:04"))
	t := e.Session().Started.Add(-26 * time.Hour)
	e.Printf("ubuntu   pts/0        %-16s %s - %s  (00:41)\n", "10.0.2.2", t.Format("Mon Jan _2 15:04"), t.Add(41*time.Minute).Format("15:04"))
	e.Printf("reboot   system boot  %-16s %s   still running\n", e.Host().Kernel, e.Host().Booted.Format("Mon Jan _2 15:04"))
	e.Printf("\nwtmp begins %s\n", e.Host().Booted.Add(-60*24*time.Hour).Format("Mon Jan _2 15:04:05 2006"))
	return 0
}

func cmdFree(e *shell.Env) int {
	o := e.Flags()
	total, used, free, shared, cache, avail := int64(4005504), int64(975172), int64(212644), int64(1104), int64(2817688), int64(2871236)
	f := func(kb int64) string {
		switch {
		case o.Has("h", "human"):
			// procps prints binary units with an "i": 3.8Gi, 952Mi.
			if kb == 0 {
				return "0B"
			}
			s := humanSize(kb * 1024)
			if last := s[len(s)-1]; last >= 'A' && last <= 'Z' {
				s += "i"
			}
			return s
		case o.Has("m", "mega"):
			return strconv.FormatInt(kb/1024, 10)
		case o.Has("g", "giga"):
			return strconv.FormatInt(kb/1024/1024, 10)
		case o.Has("b", "bytes"):
			return strconv.FormatInt(kb*1024, 10)
		}
		return strconv.FormatInt(kb, 10)
	}
	e.Print("               total        used        free      shared  buff/cache   available\n")
	e.Printf("Mem:      %10s  %10s  %10s  %10s  %10s  %10s\n", f(total), f(used), f(free), f(shared), f(cache), f(avail))
	e.Printf("Swap:     %10s  %10s  %10s\n", f(0), f(0), f(0))
	return 0
}

func cmdDf(e *shell.Env) int {
	o := e.Flags()
	if o.Has("h", "human-readable") {
		e.Print("Filesystem      Size  Used Avail Use% Mounted on\ntmpfs           392M  1.1M  391M   1% /run\n/dev/sda1        78G  4.9G   73G   7% /\ntmpfs           1.9G     0  1.9G   0% /dev/shm\ntmpfs           5.0M     0  5.0M   0% /run/lock\n/dev/sda15      105M  6.1M   99M   6% /boot/efi\ntmpfs           392M   12K  392M   1% /run/user/1000\n")
		return 0
	}
	e.Print("Filesystem     1K-blocks    Used Available Use% Mounted on\ntmpfs             400460    1104    399356   1% /run\n/dev/sda1       81106868 5124308  75965176   7% /\ntmpfs            2002752       0   2002752   0% /dev/shm\ntmpfs               5120       0      5120   0% /run/lock\n/dev/sda15        106832    6246    100586   6% /boot/efi\ntmpfs             400548      12    400536   1% /run/user/1000\n")
	return 0
}

func cmdNproc(e *shell.Env) int {
	e.Print("4\n")
	return 0
}

func cmdLscpu(e *shell.Env) int {
	e.Print(`Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          46 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   4
  On-line CPU(s) list:    0-3
Vendor ID:                GenuineIntel
  Model name:             Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
    CPU family:           6
    Model:                85
    Thread(s) per core:   2
    Core(s) per socket:   2
    Socket(s):            1
    Stepping:             7
    BogoMIPS:             4999.99
Virtualization features:
  Hypervisor vendor:      KVM
  Virtualization type:    full
Caches (sum of all):
  L1d:                    64 KiB (2 instances)
  L1i:                    64 KiB (2 instances)
  L2:                     2 MiB (2 instances)
  L3:                     35.8 MiB (1 instance)
NUMA:
  NUMA node(s):           1
  NUMA node0 CPU(s):      0-3
`)
	return 0
}

func cmdLsbRelease(e *shell.Env) int {
	o := e.Flags()
	if o.Has("a", "all") || len(e.Args) == 1 {
		fmt.Fprintln(e.Stderr, "No LSB modules are available.")
	}
	if o.Has("a", "all") {
		e.Print("Distributor ID:\tUbuntu\nDescription:\tUbuntu 24.04.1 LTS\nRelease:\t24.04\nCodename:\tnoble\n")
		return 0
	}
	if o.Has("d", "description") {
		e.Print("Description:\tUbuntu 24.04.1 LTS\n")
	}
	if o.Has("r", "release") {
		e.Print("Release:\t24.04\n")
	}
	if o.Has("c", "codename") {
		e.Print("Codename:\tnoble\n")
	}
	if o.Has("i", "id") {
		e.Print("Distributor ID:\tUbuntu\n")
	}
	return 0
}

func cmdHostnamectl(e *shell.Env) int {
	h := e.Host()
	e.Printf(` Static hostname: %s
       Icon name: computer-vm
         Chassis: vm 🖴
      Machine ID: 8f3c2b1a9d7e4f60a5b4c3d2e1f0a9b8
         Boot ID: 2d4e6f8a0b1c3d5e7f9a1b3c5d7e9f01
  Virtualization: kvm
Operating System: Ubuntu 24.04.1 LTS
          Kernel: Linux %s
    Architecture: x86-64
 Hardware Vendor: Amazon EC2
  Hardware Model: m5.large
Firmware Version: 1.0
   Firmware Date: Mon 2017-10-16
    Firmware Age: 7y 1month 2d
`, h.Hostname, h.Kernel)
	return 0
}

func cmdDmesg(e *shell.Env) int {
	if !e.User().IsRoot() {
		fmt.Fprintln(e.Stderr, "dmesg: read kernel buffer failed: Operation not permitted")
		return 1
	}
	e.Printf("[    0.000000] Linux version %s (buildd@lcy02-amd64-075) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0) #48-Ubuntu SMP PREEMPT_DYNAMIC\n[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-%s root=LABEL=cloudimg-rootfs ro console=tty1 console=ttyS0\n[    0.000000] KERNEL supported cpus:\n[    0.000000]   Intel GenuineIntel\n[    0.004000] Hypervisor detected: KVM\n[    1.284512] EXT4-fs (sda1): mounted filesystem with ordered data mode.\n", e.Host().Kernel, e.Host().Kernel)
	return 0
}

func cmdLsblk(e *shell.Env) int {
	e.Print("NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\nsda       8:0    0   80G  0 disk \n├─sda1    8:1    0 79.9G  0 part /\n├─sda14   8:14   0    4M  0 part \n└─sda15   8:15   0  106M  0 part /boot/efi\n")
	return 0
}

func cmdMount(e *shell.Env) int {
	data, _ := e.FS.AsRoot().ReadFile("/proc/mounts")
	for _, l := range splitLines(string(data)) {
		f := strings.Fields(l)
		if len(f) >= 4 {
			e.Printf("%s on %s type %s (%s)\n", f[0], f[1], f[2], f[3])
		}
	}
	return 0
}

func cmdDate(e *shell.Env) int {
	now := e.Now().UTC()
	for _, a := range e.Args[1:] {
		switch {
		case strings.HasPrefix(a, "+"):
			e.Printf("%s\n", strftime(a[1:], now))
			return 0
		case a == "-u" || a == "--utc":
		case a == "-R":
			e.Printf("%s\n", now.Format(time.RFC1123Z))
			return 0
		case a == "-I" || a == "--iso-8601":
			e.Printf("%s\n", now.Format("2006-01-02"))
			return 0
		case a == "-s" || strings.HasPrefix(a, "--set"):
			if !e.User().IsRoot() {
				fmt.Fprintln(e.Stderr, "date: cannot set date: Operation not permitted")
				return 1
			}
		}
	}
	e.Printf("%s\n", now.Format("Mon Jan _2 15:04:05 MST 2006"))
	return 0
}

func strftime(f string, t time.Time) string {
	r := strings.NewReplacer(
		"%Y", t.Format("2006"), "%m", t.Format("01"), "%d", t.Format("02"), "%H", t.Format("15"),
		"%M", t.Format("04"), "%S", t.Format("05"), "%s", strconv.FormatInt(t.Unix(), 10),
		"%y", t.Format("06"), "%b", t.Format("Jan"), "%B", t.Format("January"), "%a", t.Format("Mon"),
		"%A", t.Format("Monday"), "%Z", t.Format("MST"), "%z", t.Format("-0700"), "%F", t.Format("2006-01-02"),
		"%T", t.Format("15:04:05"), "%D", t.Format("01/02/06"), "%e", t.Format("_2"), "%j", fmt.Sprintf("%03d", t.YearDay()),
		"%N", fmt.Sprintf("%09d", t.Nanosecond()), "%%", "%", "%n", "\n",
	)
	return r.Replace(f)
}

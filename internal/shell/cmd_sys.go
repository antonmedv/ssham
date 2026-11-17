package shell

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

type proc struct {
	user        string
	pid, ppid   int
	cpu, mem    float64
	vsz, rss    int
	tty, stat   string
	start, time string
	cmd         string
}

func processes(s *Shell) []proc {
	boot := s.cfg.Host.Booted.Format("Jan02")
	ps := []proc{
		{"root", 1, 0, 0.0, 0.3, 22472, 13312, "?", "Ss", boot, "0:07", "/sbin/init"},
		{"root", 2, 0, 0.0, 0.0, 0, 0, "?", "S", boot, "0:00", "[kthreadd]"},
		{"root", 3, 2, 0.0, 0.0, 0, 0, "?", "S", boot, "0:00", "[pool_workqueue_release]"},
		{"root", 14, 2, 0.0, 0.0, 0, 0, "?", "I", boot, "0:02", "[rcu_preempt]"},
		{"root", 312, 1, 0.0, 0.4, 50356, 17408, "?", "S<s", boot, "0:03", "/usr/lib/systemd/systemd-journald"},
		{"root", 361, 1, 0.0, 0.1, 25516, 6528, "?", "Ss", boot, "0:00", "/usr/lib/systemd/systemd-udevd"},
		{"systemd+", 512, 1, 0.0, 0.2, 21452, 12160, "?", "Ss", boot, "0:01", "/usr/lib/systemd/systemd-resolved"},
		{"root", 598, 1, 0.0, 0.0, 7340, 2816, "?", "Ss", boot, "0:00", "/usr/sbin/cron -f -P"},
		{"message+", 601, 1, 0.0, 0.1, 9772, 5248, "?", "Ss", boot, "0:00", "@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"},
		{"syslog", 640, 1, 0.0, 0.1, 222508, 6016, "?", "Ssl", boot, "0:01", "/usr/sbin/rsyslogd -n -iNONE"},
		{"root", 702, 1, 0.0, 0.2, 12020, 8064, "?", "Ss", boot, "0:00", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"},
		{"root", 731, 1, 0.0, 0.0, 6104, 1920, "ttyS0", "Ss+", boot, "0:00", "/sbin/agetty -o -p -- \\u --keep-baud 115200,57600,38400,9600 - vt220"},
		{"root", 745, 1, 0.0, 0.1, 55224, 1640, "?", "Ss", boot, "0:00", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"},
		{"www-data", 746, 745, 0.0, 0.1, 55928, 5800, "?", "S", boot, "0:12", "nginx: worker process"},
		{"www-data", 747, 745, 0.0, 0.1, 55928, 5800, "?", "S", boot, "0:11", "nginx: worker process"},
		{"root", 812, 1, 0.0, 0.5, 1245860, 21476, "?", "Ssl", boot, "0:42", "/usr/bin/containerd"},
		{"root", s.pid - 2, 702, 0.0, 0.2, 14996, 9344, "?", "Ss", time.Now().Format("15:04"), "0:00", "sshd: " + s.cfg.User + " [priv]"},
		{s.cfg.User, s.pid - 1, s.pid - 2, 0.0, 0.1, 15128, 7064, "?", "S", time.Now().Format("15:04"), "0:00", "sshd: " + s.cfg.User + "@pts/0"},
		{s.cfg.User, s.pid, s.pid - 1, 0.0, 0.1, 8788, 5504, "pts/0", "Ss", time.Now().Format("15:04"), "0:00", "-bash"},
	}
	return ps
}

func processExists(s *Shell, pid int) bool {
	for _, p := range processes(s) {
		if p.pid == pid {
			return true
		}
	}
	return false
}

func cmdPs(e *Env) int {
	s := e.sh
	args := strings.Join(e.Args[1:], " ")
	ps := processes(s)
	self := proc{s.user, s.allocPID(), s.pid, 0.0, 0.1, 11320, 4480, "pts/0", "R+", time.Now().Format("15:04"), "0:00", strings.Join(e.Args, " ")}
	full := strings.Contains(args, "a") && strings.Contains(args, "u") || strings.Contains(args, "-e") || strings.Contains(args, "-A") || strings.Contains(args, "aux") || strings.Contains(args, "-ef")
	switch {
	case strings.Contains(args, "-ef") || (strings.Contains(args, "-e") && strings.Contains(args, "f")):
		e.Print("UID          PID    PPID  C STIME TTY          TIME CMD\n")
		for _, p := range append(ps, self) {
			e.Printf("%-8s %7d %7d  0 %-5s %-8s %8s %s\n", p.user, p.pid, p.ppid, p.start, p.tty, "00:00:0"+p.time[len(p.time)-1:], p.cmd)
		}
	case full:
		e.Print("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
		for _, p := range append(ps, self) {
			e.Printf("%-8s %7d %4.1f %4.1f %6d %5d %-8s %-4s %-5s %6s %s\n", p.user, p.pid, p.cpu, p.mem, p.vsz, p.rss, p.tty, p.stat, p.start, p.time, p.cmd)
		}
	default:
		e.Print("    PID TTY          TIME CMD\n")
		e.Printf("%7d pts/0    00:00:00 bash\n", s.pid)
		e.Printf("%7d pts/0    00:00:00 ps\n", self.pid)
	}
	return 0
}

func cmdTop(e *Env) int {
	s := e.sh
	up := time.Since(s.cfg.Host.Booted)
	e.Printf("top - %s up %s,  1 user,  load average: 0.08, 0.03, 0.01\n", time.Now().Format("15:04:05"), uptimeString(up))
	e.Print("Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n")
	e.Print("%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st \n")
	e.Print("MiB Mem :   3911.6 total,    207.7 free,    952.3 used,   2751.6 buff/cache     \n")
	e.Print("MiB Swap:      0.0 total,      0.0 free,      0.0 used.   2803.9 avail Mem \n\n")
	e.Print("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
	for _, p := range processes(s) {
		name := strings.Fields(p.cmd)[0]
		name = name[strings.LastIndexByte(name, '/')+1:]
		e.Printf("%7d %-8.8s  20   0 %7d %6d %6d S   0.0   %3.1f   0:00.%02d %s\n", p.pid, p.user, p.vsz, p.rss, p.rss/2, p.mem, p.pid%60, name)
	}
	if e.isTTY() && !strings.Contains(strings.Join(e.Args, " "), "-b") {
		// An interactive top would keep refreshing; wait for Ctrl+C.
		for e.Sleep(time.Hour) {
		}
	}
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

func cmdUptime(e *Env) int {
	up := time.Since(e.sh.cfg.Host.Booted)
	if len(e.Args) > 1 && (e.Args[1] == "-p" || e.Args[1] == "--pretty") {
		days := int(up.Hours()) / 24
		e.Printf("up %d weeks, %d days, %d hours, %d minutes\n", days/7, days%7, int(up.Hours())%24, int(up.Minutes())%60)
		return 0
	}
	if len(e.Args) > 1 && (e.Args[1] == "-s" || e.Args[1] == "--since") {
		e.Printf("%s\n", e.sh.cfg.Host.Booted.Format("2006-01-02 15:04:05"))
		return 0
	}
	e.Printf(" %s up %s,  1 user,  load average: 0.08, 0.03, 0.01\n", time.Now().Format("15:04:05"), uptimeString(up))
	return 0
}

func cmdW(e *Env) int {
	s := e.sh
	up := time.Since(s.cfg.Host.Booted)
	if e.Args[0] == "w" {
		e.Printf(" %s up %s,  1 user,  load average: 0.08, 0.03, 0.01\n", time.Now().Format("15:04:05"), uptimeString(up))
		e.Print("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n")
		e.Printf("%-8s pts/0    %-16s %s    0.00s  0.02s  0.00s w\n", s.cfg.User, s.cfg.ClientIP, s.cfg.Started.Format("15:04"))
		return 0
	}
	e.Printf("%-8s pts/0        %s (%s)\n", s.cfg.User, s.cfg.Started.Format("2006-01-02 15:04"), s.cfg.ClientIP)
	return 0
}

func cmdLast(e *Env) int {
	s := e.sh
	e.Printf("%-8s pts/0        %-16s %s   still logged in\n", s.cfg.User, s.cfg.ClientIP, s.cfg.Started.Format("Mon Jan _2 15:04"))
	t := s.cfg.Started.Add(-26 * time.Hour)
	e.Printf("ubuntu   pts/0        %-16s %s - %s  (00:41)\n", "10.0.2.2", t.Format("Mon Jan _2 15:04"), t.Add(41*time.Minute).Format("15:04"))
	e.Printf("reboot   system boot  %-16s %s   still running\n", s.cfg.Host.Kernel, s.cfg.Host.Booted.Format("Mon Jan _2 15:04"))
	e.Printf("\nwtmp begins %s\n", s.cfg.Host.Booted.Add(-60*24*time.Hour).Format("Mon Jan _2 15:04:05 2006"))
	return 0
}

func cmdWhoami(e *Env) int {
	e.Printf("%s\n", e.sh.user)
	return 0
}

func groupsOf(user string) []string {
	switch user {
	case "root":
		return []string{"root"}
	case "ubuntu":
		return []string{"ubuntu", "adm", "cdrom", "sudo", "dip", "lxd"}
	}
	return []string{user, "sudo"}
}

func gidOf(g string) int {
	switch g {
	case "root":
		return 0
	case "adm":
		return 4
	case "cdrom":
		return 24
	case "sudo":
		return 27
	case "dip":
		return 30
	case "lxd":
		return 105
	case "ubuntu":
		return 1000
	}
	return 1001
}

func cmdId(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	user := s.user
	if len(o.pos) > 0 {
		user = o.pos[0]
		if !userExists(s, user) {
			e.Errorf("'%s': no such user", user)
			return 1
		}
	}
	uid, _ := strconv.Atoi(uidOf(user))
	if user == s.user {
		uid = s.uid
	}
	gs := groupsOf(user)
	switch {
	case o.has("u"):
		if o.has("n") {
			e.Printf("%s\n", user)
		} else {
			e.Printf("%d\n", uid)
		}
		return 0
	case o.has("g"):
		e.Printf("%d\n", gidOf(gs[0]))
		return 0
	case o.has("G"):
		var ids []string
		for _, g := range gs {
			ids = append(ids, strconv.Itoa(gidOf(g)))
		}
		e.Printf("%s\n", strings.Join(ids, " "))
		return 0
	}
	var parts []string
	for _, g := range gs {
		parts = append(parts, fmt.Sprintf("%d(%s)", gidOf(g), g))
	}
	e.Printf("uid=%d(%s) gid=%d(%s) groups=%s\n", uid, user, gidOf(gs[0]), gs[0], strings.Join(parts, ","))
	return 0
}

func cmdGroups(e *Env) int {
	user := e.sh.user
	if len(e.Args) > 1 {
		user = e.Args[1]
		e.Printf("%s : ", user)
	}
	e.Printf("%s\n", strings.Join(groupsOf(user), " "))
	return 0
}

func userExists(s *Shell, user string) bool {
	data, _ := s.fs.ReadFile("root", "/etc/passwd")
	return strings.HasPrefix(string(data), user+":") || strings.Contains(string(data), "\n"+user+":")
}

func cmdHostname(e *Env) int {
	h := e.sh.cfg.Host.Hostname
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
			if e.sh.uid != 0 {
				fmt.Fprintln(e.Stderr, "hostname: you must be root to change the host name")
				return 1
			}
			return 0
		}
	}
	e.Printf("%s\n", h)
	return 0
}

func cmdUname(e *Env) int {
	h := e.sh.cfg.Host
	o := getopt(e.Args[1:])
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
	all := o.has("a", "all")
	for i, f := range fields {
		if all && (i == 5 || i == 6) {
			continue
		}
		if all || o.has(f.flags...) {
			out = append(out, f.val)
		}
	}
	if len(out) == 0 {
		out = []string{"Linux"}
	}
	e.Printf("%s\n", strings.Join(out, " "))
	return 0
}

func cmdFree(e *Env) int {
	o := getopt(e.Args[1:])
	total, used, free, shared, cache, avail := int64(4005504), int64(975172), int64(212644), int64(1104), int64(2817688), int64(2871236)
	f := func(kb int64) string {
		switch {
		case o.has("h", "human"):
			// procps prints binary units with an "i": 3.8Gi, 952Mi.
			s := humanSize(kb * 1024)
			if last := s[len(s)-1]; last >= 'A' && last <= 'Z' {
				s += "i"
			}
			return s
		case o.has("m", "mega"):
			return strconv.FormatInt(kb/1024, 10)
		case o.has("g", "giga"):
			return strconv.FormatInt(kb/1024/1024, 10)
		case o.has("b", "bytes"):
			return strconv.FormatInt(kb*1024, 10)
		}
		return strconv.FormatInt(kb, 10)
	}
	e.Print("               total        used        free      shared  buff/cache   available\n")
	e.Printf("Mem:      %10s  %10s  %10s  %10s  %10s  %10s\n", f(total), f(used), f(free), f(shared), f(cache), f(avail))
	e.Printf("Swap:     %10s  %10s  %10s\n", f(0), f(0), f(0))
	return 0
}

func cmdDf(e *Env) int {
	o := getopt(e.Args[1:])
	if o.has("h", "human-readable") {
		e.Print("Filesystem      Size  Used Avail Use% Mounted on\ntmpfs           392M  1.1M  391M   1% /run\n/dev/sda1        78G  4.9G   73G   7% /\ntmpfs           1.9G     0  1.9G   0% /dev/shm\ntmpfs           5.0M     0  5.0M   0% /run/lock\n/dev/sda15      105M  6.1M   99M   6% /boot/efi\ntmpfs           392M   12K  392M   1% /run/user/1000\n")
		return 0
	}
	e.Print("Filesystem     1K-blocks    Used Available Use% Mounted on\ntmpfs             400460    1104    399356   1% /run\n/dev/sda1       81106868 5124308  75965176   7% /\ntmpfs            2002752       0   2002752   0% /dev/shm\ntmpfs               5120       0      5120   0% /run/lock\n/dev/sda15        106832    6246    100586   6% /boot/efi\ntmpfs             400548      12    400536   1% /run/user/1000\n")
	return 0
}

func cmdNproc(e *Env) int {
	e.Print("4\n")
	return 0
}

func cmdLscpu(e *Env) int {
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

func cmdLsbRelease(e *Env) int {
	o := getopt(e.Args[1:])
	if o.has("a", "all") || len(e.Args) == 1 {
		fmt.Fprintln(e.Stderr, "No LSB modules are available.")
	}
	if o.has("a", "all") {
		e.Print("Distributor ID:\tUbuntu\nDescription:\tUbuntu 24.04.1 LTS\nRelease:\t24.04\nCodename:\tnoble\n")
		return 0
	}
	if o.has("d", "description") {
		e.Print("Description:\tUbuntu 24.04.1 LTS\n")
	}
	if o.has("r", "release") {
		e.Print("Release:\t24.04\n")
	}
	if o.has("c", "codename") {
		e.Print("Codename:\tnoble\n")
	}
	if o.has("i", "id") {
		e.Print("Distributor ID:\tUbuntu\n")
	}
	return 0
}

func cmdHostnamectl(e *Env) int {
	h := e.sh.cfg.Host
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

func cmdDate(e *Env) int {
	now := time.Now().UTC()
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
			if e.sh.uid != 0 {
				fmt.Fprintln(e.Stderr, "date: cannot set date: Operation not permitted")
				return 1
			}
		}
	}
	e.Printf("%s\n", now.Format("Mon Jan _2 03:04:05 PM MST 2006"))
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

func cmdSleep(e *Env) int {
	var total time.Duration
	for _, a := range e.Args[1:] {
		mult := time.Second
		switch {
		case strings.HasSuffix(a, "m"):
			mult, a = time.Minute, strings.TrimSuffix(a, "m")
		case strings.HasSuffix(a, "h"):
			mult, a = time.Hour, strings.TrimSuffix(a, "h")
		case strings.HasSuffix(a, "s"):
			a = strings.TrimSuffix(a, "s")
		}
		f, err := strconv.ParseFloat(a, 64)
		if err != nil {
			e.Errorf("invalid time interval '%s'", a)
			return 1
		}
		total += time.Duration(f * float64(mult))
	}
	if len(e.Args) == 1 {
		fmt.Fprintln(e.Stderr, "sleep: missing operand\nTry 'sleep --help' for more information.")
		return 1
	}
	if !e.Sleep(total) {
		return 130
	}
	return 0
}

func cmdEnv(e *Env) int {
	// env VAR=x cmd ... runs cmd; plain env prints the environment.
	args := e.Args[1:]
	for len(args) > 0 && (strings.HasPrefix(args[0], "-") || isAssignment(args[0])) {
		args = args[1:]
	}
	if len(args) > 0 {
		return e.sh.run(e.Ctx, args, e.Stdin, e.Stdout, e.Stderr)
	}
	if e.Args[0] == "printenv" && len(e.Args) > 1 {
		status := 1
		for _, n := range e.Args[1:] {
			if v, ok := e.sh.vars[n]; ok && e.sh.exports[n] {
				e.Printf("%s\n", v)
				status = 0
			}
		}
		return status
	}
	for _, kv := range e.sh.sortedVars(true) {
		e.Printf("%s\n", kv)
	}
	return 0
}

func cmdClear(e *Env) int {
	e.Print("\x1b[H\x1b[2J\x1b[3J")
	return 0
}

func cmdCrontab(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "u")
	user := s.user
	if u, ok := o.val("u"); ok {
		if s.uid != 0 && u != s.user {
			fmt.Fprintf(e.Stderr, "must be privileged to use -u\n")
			return 1
		}
		user = u
	}
	p := "/var/spool/cron/crontabs/" + user
	switch {
	case o.has("l"):
		data, err := s.fs.ReadFile("root", p)
		if err != nil || len(data) == 0 {
			fmt.Fprintf(e.Stderr, "no crontab for %s\n", user)
			return 1
		}
		e.Print(string(data))
		return 0
	case o.has("r"):
		if err := s.fs.Remove("root", p, false); err != nil {
			fmt.Fprintf(e.Stderr, "no crontab for %s\n", user)
			return 1
		}
		return 0
	case o.has("e"):
		fmt.Fprintf(e.Stderr, "no crontab for %s - using an empty one\n", user)
		fmt.Fprintln(e.Stderr, "crontab: \"/usr/bin/sensible-editor\" exited with status 1")
		return 1
	}
	var data string
	if len(o.pos) == 0 || o.pos[0] == "-" {
		data = e.ReadStdin()
	} else {
		b, err := s.fs.ReadFile(s.user, s.resolve(o.pos[0]))
		if err != nil {
			fmt.Fprintf(e.Stderr, "%s: %s\n", o.pos[0], err)
			return 1
		}
		data = string(b)
	}
	s.log.Event("crontab_install", "user", user, "content", truncate(data, 8192))
	_ = s.fs.WriteFile("root", p, []byte(data), false)
	return 0
}

func cmdSystemctl(e *Env) int {
	o := getopt(e.Args[1:])
	if len(o.pos) == 0 {
		e.Print("  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION\n  cron.service                loaded active running Regular background program processing daemon\n  nginx.service               loaded active running A high performance web server and a reverse proxy server\n  ssh.service                 loaded active running OpenBSD Secure Shell server\n  systemd-journald.service    loaded active running Journal Service\n  systemd-resolved.service    loaded active running Network Name Resolution\n\n5 loaded units listed.\n")
		return 0
	}
	verb := o.pos[0]
	unit := ""
	if len(o.pos) > 1 {
		unit = strings.TrimSuffix(o.pos[1], ".service")
	}
	switch verb {
	case "status":
		if unit == "" {
			unit = "ssh"
		}
		e.Printf("● %s.service - %s\n     Loaded: loaded (/usr/lib/systemd/system/%s.service; enabled; preset: enabled)\n     Active: active (running) since %s; %s ago\n   Main PID: %d (%s)\n      Tasks: 1 (limit: 4613)\n     Memory: 4.2M (peak: 5.1M)\n        CPU: 213ms\n",
			unit, unit, unit, e.sh.cfg.Host.Booted.Format("Mon 2006-01-02 15:04:05 MST"), uptimeString(time.Since(e.sh.cfg.Host.Booted)), 700+len(unit)*13, unit)
		return 0
	case "start", "stop", "restart", "reload", "enable", "disable", "daemon-reload", "mask", "unmask":
		if e.sh.uid != 0 {
			fmt.Fprintf(e.Stderr, "Failed to %s %s.service: Interactive authentication required.\nSee system logs and 'systemctl status %s.service' for details.\n", verb, unit, unit)
			return 1
		}
		e.sh.log.Event("service_change", "verb", verb, "unit", unit)
		if verb == "enable" {
			fmt.Fprintf(e.Stderr, "Created symlink /etc/systemd/system/multi-user.target.wants/%s.service → /etc/systemd/system/%s.service.\n", unit, unit)
		}
		return 0
	case "is-active":
		e.Print("active\n")
		return 0
	}
	return 0
}

func cmdService(e *Env) int {
	if len(e.Args) < 3 {
		fmt.Fprintln(e.Stderr, "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]")
		return 1
	}
	return cmdSystemctl(&Env{Ctx: e.Ctx, Args: []string{"systemctl", e.Args[2], e.Args[1]}, Stdin: e.Stdin, Stdout: e.Stdout, Stderr: e.Stderr, sh: e.sh})
}

func cmdApt(e *Env) int {
	o := getopt(e.Args[1:], "o")
	if len(o.pos) == 0 {
		e.Printf("%s 2.7.14 (amd64)\nUsage: %s [options] command\n", e.Args[0], e.Args[0])
		return 1
	}
	verb := o.pos[0]
	needRoot := map[string]bool{"install": true, "update": true, "upgrade": true, "remove": true, "purge": true, "autoremove": true, "dist-upgrade": true, "full-upgrade": true}
	if needRoot[verb] && e.sh.uid != 0 {
		fmt.Fprintln(e.Stderr, "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)")
		fmt.Fprintln(e.Stderr, "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?")
		return 100
	}
	switch verb {
	case "update":
		for _, l := range []string{
			"Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease",
			"Get:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease [126 kB]",
			"Hit:3 http://archive.ubuntu.com/ubuntu noble-backports InRelease",
			"Get:4 http://security.ubuntu.com/ubuntu noble-security InRelease [126 kB]",
			"Fetched 252 kB in 1s (318 kB/s)",
			"Reading package lists... Done",
		} {
			if !e.Sleep(time.Duration(200+rand.IntN(400)) * time.Millisecond) {
				return 130
			}
			e.Printf("%s\n", l)
		}
	case "install":
		pkgs := o.pos[1:]
		e.sh.log.Event("package_install", "packages", strings.Join(pkgs, " "))
		e.Print("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n")
		if !e.Sleep(800 * time.Millisecond) {
			return 130
		}
		for _, p := range pkgs {
			if strings.HasPrefix(p, "-") {
				continue
			}
			e.Printf("%s is already the newest version (%d.%d-%dubuntu%d).\n", p, 1+len(p)%4, len(p)%10, len(p)%3+1, len(p)%5)
		}
		e.Print("0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n")
	case "upgrade", "dist-upgrade", "full-upgrade":
		e.Print("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nCalculating upgrade... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
	case "list":
		e.Print("Listing... Done\n")
	default:
		e.Print("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n")
	}
	return 0
}

func cmdDmesg(e *Env) int {
	if e.sh.uid != 0 {
		fmt.Fprintln(e.Stderr, "dmesg: read kernel buffer failed: Operation not permitted")
		return 1
	}
	e.Printf("[    0.000000] Linux version %s (buildd@lcy02-amd64-075) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0) #48-Ubuntu SMP PREEMPT_DYNAMIC\n[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-%s root=LABEL=cloudimg-rootfs ro console=tty1 console=ttyS0\n[    0.000000] KERNEL supported cpus:\n[    0.000000]   Intel GenuineIntel\n[    0.004000] Hypervisor detected: KVM\n[    1.284512] EXT4-fs (sda1): mounted filesystem with ordered data mode.\n", e.sh.cfg.Host.Kernel, e.sh.cfg.Host.Kernel)
	return 0
}

func cmdLsblk(e *Env) int {
	e.Print("NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\nsda       8:0    0   80G  0 disk \n├─sda1    8:1    0 79.9G  0 part /\n├─sda14   8:14   0    4M  0 part \n└─sda15   8:15   0  106M  0 part /boot/efi\n")
	return 0
}

func cmdMount(e *Env) int {
	data, _ := e.sh.fs.ReadFile("root", "/proc/mounts")
	for _, l := range splitLines(string(data)) {
		f := strings.Fields(l)
		if len(f) >= 4 {
			e.Printf("%s on %s type %s (%s)\n", f[0], f[1], f[2], f[3])
		}
	}
	return 0
}

func cmdReboot(e *Env) int {
	if e.sh.uid != 0 {
		fmt.Fprintln(e.Stderr, "Call to Reboot failed: Interactive authentication required.")
		return 1
	}
	e.sh.log.Event("reboot", "command", strings.Join(e.Args, " "))
	fmt.Fprintf(e.Stderr, "\nBroadcast message from root@%s on pts/0 (%s):\n\nThe system will %s now!\n\n", e.sh.cfg.Host.Hostname, time.Now().Format("Mon 2006-01-02 15:04:05 MST"), map[bool]string{true: "power off", false: "reboot"}[e.Args[0] == "shutdown" || e.Args[0] == "poweroff" || e.Args[0] == "halt"])
	e.sh.exited = true
	e.sh.exitCode = 0
	return 0
}

func cmdUseradd(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "p", "d", "s", "g", "G", "c", "u", "password", "home", "shell")
	if s.uid != 0 {
		fmt.Fprintf(e.Stderr, "%s: Permission denied.\n%s: cannot lock /etc/passwd; try again later.\n", e.Args[0], e.Args[0])
		return 1
	}
	if len(o.pos) == 0 {
		fmt.Fprintf(e.Stderr, "Usage: %s [options] LOGIN\n", e.Args[0])
		return 2
	}
	user := o.pos[len(o.pos)-1]
	if e.Args[0] == "usermod" {
		s.log.Event("user_modify", "user", user, "args", strings.Join(e.Args[1:], " "))
		return 0
	}
	if userExists(s, user) {
		fmt.Fprintf(e.Stderr, "%s: user '%s' already exists\n", e.Args[0], user)
		return 9
	}
	pw, _ := o.val("p", "password")
	s.log.Event("user_add", "user", user, "password_hash", pw, "args", strings.Join(e.Args[1:], " "))
	uid := 1002 + rand.IntN(50)
	_ = s.fs.WriteFile("root", "/etc/passwd", []byte(fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/sh\n", user, uid, uid, user)), true)
	_ = s.fs.WriteFile("root", "/etc/shadow", []byte(fmt.Sprintf("%s:%s:20044:0:99999:7:::\n", user, map[bool]string{true: "!", false: pw}[pw == ""])), true)
	if e.Args[0] == "adduser" || o.has("m", "create-home") {
		_ = s.fs.Mkdir("root", "/home/"+user, true)
		_ = s.fs.Chown("root", "/home/"+user, user, user)
	}
	if e.Args[0] == "adduser" {
		e.Printf("info: Adding user `%s' ...\ninfo: Selecting UID/GID from range 1000 to 59999 ...\ninfo: Adding new group `%s' (%d) ...\ninfo: Adding new user `%s' (%d) with group `%s (%d)' ...\ninfo: Creating home directory `/home/%s' ...\ninfo: Copying files from `/etc/skel' ...\n", user, user, uid, user, uid, user, uid, user)
		for i := 0; i < 2; i++ {
			label := "New password: "
			if i == 1 {
				label = "Retype new password: "
			}
			pw, err := s.term.ReadLine(label, false)
			if err != nil {
				return 1
			}
			s.log.Event("password_entered", "context", "adduser", "user", user, "password", pw)
		}
		e.Print("passwd: password updated successfully\n")
	}
	return 0
}

func cmdChpasswd(e *Env) int {
	s := e.sh
	data := e.ReadStdin()
	for _, l := range splitLines(data) {
		user, pw, ok := strings.Cut(l, ":")
		if !ok {
			fmt.Fprintf(e.Stderr, "chpasswd: line 1: missing new password\n")
			return 1
		}
		s.log.Event("password_change", "method", "chpasswd", "user", user, "password", pw)
		if s.uid != 0 {
			fmt.Fprintf(e.Stderr, "chpasswd: (user %s) pam_chauthtok() failed, error:\nAuthentication token manipulation error\nchpasswd: (line 1, user %s) password not changed\n", user, user)
			return 1
		}
	}
	return 0
}

func cmdPasswd(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:])
	target := s.user
	if len(o.pos) > 0 {
		target = o.pos[0]
		if s.uid != 0 && target != s.user {
			fmt.Fprintf(e.Stderr, "passwd: You may not view or modify password information for %s.\n", target)
			return 1
		}
	}
	if o.has("stdin") {
		pw := strings.TrimSpace(e.ReadStdin())
		s.log.Event("password_change", "method", "passwd --stdin", "user", target, "password", pw)
		e.Print("passwd: unrecognized option '--stdin'\n")
		return 1
	}
	e.Printf("Changing password for %s.\n", target)
	prompts := []string{"Current password: ", "New password: ", "Retype new password: "}
	if s.uid == 0 {
		prompts = prompts[1:]
	}
	var pws []string
	for _, p := range prompts {
		pw, err := readSecret(e, p)
		if err != nil {
			fmt.Fprintln(e.Stderr, "passwd: Authentication token manipulation error\npasswd: password unchanged")
			return 10
		}
		pws = append(pws, pw)
	}
	s.log.Event("password_change", "method", "passwd", "user", target, "passwords", strings.Join(pws, "\x00"))
	if pws[len(pws)-1] != pws[len(pws)-2] {
		fmt.Fprintln(e.Stderr, "Sorry, passwords do not match.\npasswd: Authentication token manipulation error\npasswd: password unchanged")
		return 10
	}
	e.Print("passwd: password updated successfully\n")
	return 0
}

// readSecret reads a hidden line from the terminal, or a line from stdin
// when input is piped.
func readSecret(e *Env, prompt string) (string, error) {
	if _, ok := e.Stdin.(*ttyReader); ok {
		return e.sh.term.ReadLine(prompt, false)
	}
	var b strings.Builder
	var c [1]byte
	for {
		n, err := e.Stdin.Read(c[:])
		if n == 0 || err != nil {
			if b.Len() == 0 {
				return "", err
			}
			break
		}
		if c[0] == '\n' {
			break
		}
		b.WriteByte(c[0])
	}
	return b.String(), nil
}

func cmdSudo(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	login, shell, list := false, false, false
	user := "root"
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		a := args[0]
		args = args[1:]
		switch a {
		case "-i", "--login":
			login = true
		case "-s", "--shell":
			shell = true
		case "-l", "--list":
			list = true
		case "-u", "--user":
			if len(args) > 0 {
				user = args[0]
				args = args[1:]
			}
		case "-S", "--stdin", "-n", "-E", "-H", "-k", "-v", "--":
		}
		if a == "--" {
			break
		}
	}
	if !list && !login && !shell && len(args) == 0 {
		fmt.Fprintln(e.Stderr, "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\nusage: sudo [-ABbEHkNnPS] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i | -s] [command [arg ...]]")
		return 1
	}
	if s.uid != 0 && !s.sudoAuthed {
		ok := false
		for attempt := 0; attempt < 3; attempt++ {
			pw, err := readSecret(e, fmt.Sprintf("[sudo] password for %s: ", s.user))
			if err != nil {
				return 1
			}
			s.log.Event("password_entered", "context", "sudo", "user", s.user, "password", pw)
			if pw != "" {
				ok = true
				break
			}
			fmt.Fprintln(e.Stderr, "Sorry, try again.")
		}
		if !ok {
			fmt.Fprintln(e.Stderr, "sudo: 3 incorrect password attempts")
			return 1
		}
		s.sudoAuthed = true
	}
	if list {
		e.Printf("Matching Defaults entries for %s on %s:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin, use_pty\n\nUser %s may run the following commands on %s:\n    (ALL : ALL) ALL\n", s.user, s.cfg.Host.Hostname, s.user, s.cfg.Host.Hostname)
		return 0
	}
	home := "/root"
	uid := 0
	if user != "root" {
		home = "/home/" + user
		uid = 1000
	}
	if login || shell || (len(args) > 0 && isShellName(args[0]) && len(args) == 1) || (len(args) > 0 && args[0] == "su") {
		cwd := ""
		if login || (len(args) > 1 && args[0] == "su" && (args[1] == "-" || args[1] == "-l")) {
			cwd = home
		}
		if len(args) > 0 && args[0] != "su" && !isShellName(args[0]) {
			// sudo -i cmd / sudo -s cmd runs the command as root.
			return runAs(e, user, home, uid, args)
		}
		s.pushIdentity(user, home, uid, cwd)
		return 0
	}
	return runAs(e, user, home, uid, args)
}

func runAs(e *Env, user, home string, uid int, args []string) int {
	s := e.sh
	saved := identity{user: s.user, home: s.home, cwd: s.cwd, uid: s.uid}
	s.user, s.home, s.uid = user, home, uid
	defer func() { s.user, s.home, s.uid, s.cwd = saved.user, saved.home, saved.uid, saved.cwd }()
	return s.run(e.Ctx, args, e.Stdin, e.Stdout, e.Stderr)
}

func cmdSu(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	user := "root"
	login := false
	var cmd string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-" || a == "-l" || a == "--login":
			login = true
		case a == "-c" || a == "--command":
			if i+1 < len(args) {
				cmd = args[i+1]
				i++
			}
		case !strings.HasPrefix(a, "-"):
			user = a
		}
	}
	if !userExists(s, user) {
		fmt.Fprintf(e.Stderr, "su: user %s does not exist or the user entry does not contain all the required fields\n", user)
		return 1
	}
	if s.uid != 0 {
		pw, err := readSecret(e, "Password: ")
		if err != nil {
			return 1
		}
		s.log.Event("password_entered", "context", "su", "user", user, "password", pw)
		if !e.Sleep(time.Duration(1500+rand.IntN(1500)) * time.Millisecond) {
			return 1
		}
		fmt.Fprintln(e.Stderr, "su: Authentication failure")
		return 1
	}
	home := "/root"
	uid := 0
	if user != "root" {
		home, uid = "/home/"+user, 1000
	}
	if cmd != "" {
		saved := identity{user: s.user, home: s.home, cwd: s.cwd, uid: s.uid}
		s.user, s.home, s.uid = user, home, uid
		defer func() { s.user, s.home, s.uid, s.cwd = saved.user, saved.home, saved.uid, saved.cwd }()
		return s.execString(e.Ctx, cmd, e.Stdin, e.Stdout, e.Stderr)
	}
	cwd := ""
	if login {
		cwd = home
	}
	s.pushIdentity(user, home, uid, cwd)
	return 0
}

// cmdShell handles sh/bash: -c strings, script files, and nested
// interactive shells.
func cmdShell(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-c" {
		args = args[1:]
	}
	if len(args) >= 2 && args[0] == "-c" {
		s.log.Event("exec_inline", "shell", e.Args[0], "script", truncate(args[1], 8192))
		savedArgs := s.args
		s.args = append([]string{e.Args[0]}, args[2:]...)
		defer func() { s.args = savedArgs }()
		return s.execString(e.Ctx, args[1], e.Stdin, e.Stdout, e.Stderr)
	}
	if len(args) >= 1 {
		p := s.resolve(args[0])
		data, err := s.fs.ReadFile(s.user, p)
		if err != nil {
			fmt.Fprintf(e.Stderr, "%s: %s: %s\n", e.Args[0], args[0], err)
			return 127
		}
		return s.runScript(&Env{Ctx: e.Ctx, Args: args, Stdin: e.Stdin, Stdout: e.Stdout, Stderr: e.Stderr, sh: s}, p, data)
	}
	if _, ok := e.Stdin.(*ttyReader); !ok {
		// Script piped in: curl ... | sh
		script := e.ReadStdin()
		s.log.Event("exec_inline", "shell", e.Args[0], "script", truncate(script, 8192))
		return s.execString(e.Ctx, script, strings.NewReader(""), e.Stdout, e.Stderr)
	}
	s.pushIdentity(s.user, s.home, s.uid, "")
	return 0
}

func cmdInterpreter(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	for i, a := range args {
		if a == "-c" || a == "-e" {
			code := ""
			if i+1 < len(args) {
				code = args[i+1]
			}
			s.log.Event("exec_inline", "interpreter", e.Args[0], "script", truncate(code, 8192))
			return 0
		}
		if a == "-V" || a == "--version" {
			if strings.HasPrefix(e.Args[0], "python") {
				e.Print("Python 3.12.3\n")
			} else {
				e.Print("\nThis is perl 5, version 38, subversion 2 (v5.38.2) built for x86_64-linux-gnu-thread-multi\n")
			}
			return 0
		}
	}
	if len(args) > 0 {
		if data, err := s.fs.ReadFile(s.user, s.resolve(args[0])); err == nil {
			s.log.Event("exec_script", "interpreter", e.Args[0], "path", s.resolve(args[0]), "content", truncate(string(data), 8192))
			return 0
		}
		fmt.Fprintf(e.Stderr, "%s: can't open file '%s': [Errno 2] No such file or directory\n", e.Args[0], s.resolve(args[0]))
		return 2
	}
	if _, ok := e.Stdin.(*ttyReader); !ok {
		s.log.Event("exec_inline", "interpreter", e.Args[0], "script", truncate(e.ReadStdin(), 8192))
		return 0
	}
	if strings.HasPrefix(e.Args[0], "python") {
		e.Print("Python 3.12.3 (main, Sep 11 2024, 14:17:37) [GCC 13.2.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n")
		for {
			line, err := s.term.ReadLine(">>> ", true)
			if err != nil {
				e.Print("\n")
				return 0
			}
			s.log.Event("stdin", "interpreter", "python", "line", line)
			if l := strings.TrimSpace(line); l == "exit()" || l == "quit()" {
				return 0
			} else if l != "" {
				e.Printf("Traceback (most recent call last):\n  File \"<stdin>\", line 1, in <module>\nModuleNotFoundError: No module named '%s'\n", strings.Fields(strings.NewReplacer("(", " ", ".", " ").Replace(l))[0])
			}
		}
	}
	return 0
}

func cmdEditor(e *Env) int {
	s := e.sh
	if len(e.Args) > 1 {
		s.log.Event("editor_open", "editor", e.Args[0], "path", s.resolve(e.Args[len(e.Args)-1]))
	}
	if s.cfg.Term == "" {
		fmt.Fprintf(e.Stderr, "Error opening terminal: unknown.\n")
		return 1
	}
	fmt.Fprintf(e.Stderr, "Error opening terminal: %s.\n", s.cfg.Term)
	return 1
}

func cmdArchive(e *Env) int {
	// tar, gzip, unzip and friends: pretend to work on files that exist.
	s := e.sh
	o := getopt(e.Args[1:], "f", "C")
	if f, ok := o.val("f"); ok {
		if _, err := s.fs.Stat(s.user, s.resolve(f)); err != nil && !o.has("c") {
			fmt.Fprintf(e.Stderr, "%s: %s: Cannot open: %s\n%s: Error is not recoverable: exiting now\n", e.Args[0], f, err, e.Args[0])
			return 2
		}
		if o.has("x") {
			s.log.Event("archive_extract", "path", s.resolve(f))
		}
		return 0
	}
	for _, f := range o.pos {
		if _, err := s.fs.Stat(s.user, s.resolve(f)); err != nil {
			fmt.Fprintf(e.Stderr, "%s: %s: %s\n", e.Args[0], f, err)
			return 1
		}
	}
	return 0
}

func cmdNohup(e *Env) int {
	if len(e.Args) < 2 {
		fmt.Fprintln(e.Stderr, "nohup: missing operand")
		return 125
	}
	if e.isTTY() {
		fmt.Fprintln(e.Stderr, "nohup: ignoring input and appending output to 'nohup.out'")
	}
	return e.sh.run(e.Ctx, e.Args[1:], strings.NewReader(""), e.Stdout, e.Stderr)
}

func cmdTimeout(e *Env) int {
	args := e.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	if len(args) < 2 {
		fmt.Fprintln(e.Stderr, "timeout: missing operand")
		return 125
	}
	return e.sh.run(e.Ctx, args[1:], e.Stdin, e.Stdout, e.Stderr)
}

func cmdDd(e *Env) int {
	var count, bs int64 = 0, 512
	for _, a := range e.Args[1:] {
		k, v, _ := strings.Cut(a, "=")
		n, _ := strconv.ParseInt(strings.TrimRight(v, "KMGkmgB"), 10, 64)
		switch strings.ToUpper(strings.TrimLeft(v, "0123456789")) {
		case "K":
			n *= 1024
		case "M":
			n *= 1 << 20
		case "G":
			n *= 1 << 30
		}
		switch k {
		case "count":
			count = n
		case "bs":
			bs = n
		}
	}
	total := count * bs
	fmt.Fprintf(e.Stderr, "%d+0 records in\n%d+0 records out\n%d bytes (%s) copied, 0.0123 s, %s/s\n", count, count, total, humanSize(total), humanSize(total*80))
	return 0
}

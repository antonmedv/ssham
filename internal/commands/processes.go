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
		shell.Command{Name: "ps", Run: cmdPs},
		shell.Command{Name: "top", Aliases: []string{"htop"}, Run: cmdTop},
		shell.Command{Name: "kill", Run: cmdKill},
	)
}

func cmdPs(e *shell.Env) int {
	args := strings.Join(e.Args[1:], " ")
	ps := processes(e)
	self := proc{e.User().Name, e.NewPID(), e.Session().PID, 0.0, 0.1, 11320, 4480, "pts/0", "R+", e.Now().Format("15:04"), "0:00", strings.Join(e.Args, " ")}
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
		e.Printf("%7d pts/0    00:00:00 bash\n", e.Session().PID)
		e.Printf("%7d pts/0    00:00:00 ps\n", self.pid)
	}
	return 0
}

func cmdTop(e *shell.Env) int {
	up := e.Now().Sub(e.Host().Booted)
	e.Printf("top - %s up %s,  1 user,  load average: 0.08, 0.03, 0.01\n", e.Now().Format("15:04:05"), uptimeString(up))
	e.Print("Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n")
	e.Print("%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st \n")
	e.Print("MiB Mem :   3911.6 total,    207.7 free,    952.3 used,   2751.6 buff/cache     \n")
	e.Print("MiB Swap:      0.0 total,      0.0 free,      0.0 used.   2803.9 avail Mem \n\n")
	e.Print("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
	for _, p := range processes(e) {
		name := strings.Fields(p.cmd)[0]
		name = name[strings.LastIndexByte(name, '/')+1:]
		e.Printf("%7d %-8.8s  20   0 %7d %6d %6d S   0.0   %3.1f   0:00.%02d %s\n", p.pid, p.user, p.vsz, p.rss, p.rss/2, p.mem, p.pid%60, name)
	}
	if e.IsTTY() && !strings.Contains(strings.Join(e.Args, " "), "-b") {
		// An interactive top would keep refreshing; wait for Ctrl+C.
		for e.Sleep(time.Hour) {
		}
	}
	return 0
}

type proc struct {
	user        string
	pid, ppid   int
	cpu, mem    float64
	vsz, rss    int
	tty, stat   string
	start, time string
	cmd         string
}

func processes(e *shell.Env) []proc {
	boot := e.Host().Booted.Format("Jan02")
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
		{"root", e.Session().PID - 2, 702, 0.0, 0.2, 14996, 9344, "?", "Ss", e.Now().Format("15:04"), "0:00", "sshd: " + e.Session().LoginUser + " [priv]"},
		{e.Session().LoginUser, e.Session().PID - 1, e.Session().PID - 2, 0.0, 0.1, 15128, 7064, "?", "S", e.Now().Format("15:04"), "0:00", "sshd: " + e.Session().LoginUser + "@pts/0"},
		{e.Session().LoginUser, e.Session().PID, e.Session().PID - 1, 0.0, 0.1, 8788, 5504, "pts/0", "Ss", e.Now().Format("15:04"), "0:00", "-bash"},
	}
	return ps
}

func processExists(e *shell.Env, pid int) bool {
	for _, p := range processes(e) {
		if p.pid == pid {
			return true
		}
	}
	return false
}
func cmdKill(e *shell.Env) int {
	args := e.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(e.Stderr, "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]")
		return 2
	}
	if args[0] == "-l" {
		e.Print(" 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n 6) SIGABRT\t 7) SIGBUS\t 8) SIGFPE\t 9) SIGKILL\t10) SIGUSR1\n11) SIGSEGV\t12) SIGUSR2\t13) SIGPIPE\t14) SIGALRM\t15) SIGTERM\n")
		return 0
	}
	status := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		pid, err := strconv.Atoi(a)
		if err != nil {
			fmt.Fprintf(e.Stderr, "-bash: kill: %s: arguments must be process or job IDs\n", a)
			status = 1
			continue
		}
		if !processExists(e, pid) {
			fmt.Fprintf(e.Stderr, "-bash: kill: (%d) - No such process\n", pid)
			status = 1
		} else if !e.User().IsRoot() {
			fmt.Fprintf(e.Stderr, "-bash: kill: (%d) - Operation not permitted\n", pid)
			status = 1
		}
	}
	return status
}

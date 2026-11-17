package commands

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "ps", Usage: "[-o COL1,COL2=HEADER] [-T]", Run: cmdPs},
		shell.Command{Name: "top", Dir: "/usr/bin", Usage: "[-b] [-n COUNT] [-d SECONDS]", Run: cmdTop},
		shell.Command{Name: "kill", Usage: "[-l] [-SIG] PID...", Run: cmdKill},
		shell.Command{Name: "killall", Dir: "/usr/bin", Usage: "[-l] [-q] [-SIG] PROCESS_NAME...", Run: cmdKillall},
	)
}

type proc struct {
	pid, ppid int
	vsz       int // KB
	stat      string
	cmd       string
}

// processes is what runs on the camera, plus the attacker's session.
func processes(e *shell.Env) []proc {
	pid := e.Session().PID
	return []proc{
		{1, 0, 1240, "S", "init"},
		{2, 0, 0, "SW", "[kthreadd]"},
		{3, 2, 0, "IW<", "[rcu_gp]"},
		{6, 2, 0, "SW", "[ksoftirqd/0]"},
		{7, 2, 0, "IW", "[rcu_preempt]"},
		{38, 2, 0, "SW", "[kswapd0]"},
		{214, 2, 0, "SW", "[jffs2_gcd_mtd4]"},
		{561, 1, 1236, "S", "/sbin/syslogd -C64"},
		{612, 1, 38472, "S", "./ipcam"},
		{731, 1, 1052, "S", "/usr/sbin/dropbear -R -p 22"},
		{pid - 1, 731, 1088, "S", "/usr/sbin/dropbear -R -p 22"},
		{pid, pid - 1, 1244, "S", "-sh"},
	}
}

func cmdPs(e *shell.Env) int {
	self := proc{e.NewPID(), e.Session().PID, 1240, "R", strings.Join(e.Args, " ")}
	e.Print("  PID USER       VSZ STAT COMMAND\n")
	for _, p := range append(processes(e), self) {
		e.Printf("%5d root     %5d %-4s %s\n", p.pid, p.vsz, p.stat, p.cmd)
	}
	return 0
}

func cmdTop(e *shell.Env) int {
	o := e.Flags("n", "d")
	count := 0 // forever
	if n, ok := o.Value("n"); ok {
		count, _ = strconv.Atoi(n)
	}
	for i := 0; count == 0 || i < count; i++ {
		if i > 0 && !e.Sleep(5*time.Second) {
			return 0
		}
		e.Print("Mem: 34048K used, 25012K free, 0K shrd, 1876K buff, 17536K cached\n")
		e.Print("CPU:   2% usr   3% sys   0% nic  94% idle   0% io   0% irq   0% sirq\n")
		e.Print("Load average: 0.52 0.48 0.47 2/63 742\n")
		e.Print("  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND\n")
		for _, p := range processes(e) {
			cpu := 0
			if p.pid == 612 {
				cpu = 4
			}
			e.Printf("%5d %5d root     %-4s %5d %3d%% %3d%% %s\n", p.pid, p.ppid, p.stat, p.vsz, p.vsz*100/59060, cpu, p.cmd)
		}
		if count == 0 && !e.IsTTY() {
			count = 1 // top in a pipe runs once, like top -b -n 1
		}
	}
	return 0
}

var signals = []string{"HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "POLL", "PWR", "SYS"}

// cmdKill behaves like ash's kill builtin, which is what `kill` runs.
func cmdKill(e *shell.Env) int {
	// By name, kill is ash's builtin, which reports errors as the shell.
	prefix := "sh: "
	if e.Args[0] != "kill" {
		prefix = "kill: " // run as /bin/kill or busybox kill
	}
	args := e.Args[1:]
	if len(args) == 0 {
		return e.Usage()
	}
	if args[0] == "-l" {
		for i, s := range signals {
			e.Printf("%2d) %s\n", i+1, s)
		}
		return 0
	}
	status := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		pid, err := strconv.Atoi(a)
		if err != nil {
			fmt.Fprintf(e.Stderr, "%sillegal number: %s\n", prefix, a)
			status = 1
			continue
		}
		found := false
		for _, p := range processes(e) {
			found = found || p.pid == pid
		}
		if !found {
			fmt.Fprintf(e.Stderr, "%scan't kill pid %d: No such process\n", prefix, pid)
			status = 1
		}
	}
	return status
}

func cmdKillall(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		return e.Usage()
	}
	status := 0
	for _, name := range o.Args {
		found := false
		for _, p := range processes(e) {
			fields := strings.Fields(p.cmd)
			found = found || path.Base(fields[0]) == name
		}
		if !found {
			if !o.Has("q") {
				e.Errorf("%s: no process killed", name)
			}
			status = 1
		}
	}
	return status
}

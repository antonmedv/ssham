package commands

import (
	"fmt"
	"sort"
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
	vsz       int // kB
	stat      string
	cmd       string
	comm      string
}

// processes reads the process list from /proc, as BusyBox ps does.
func processes(e *shell.Env) []proc {
	e.SyncProc()
	root := e.FS.AsRoot()
	entries, _ := root.ReadDir("/proc")
	var out []proc
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name)
		if err != nil {
			continue
		}
		dir := "/proc/" + ent.Name + "/"
		stat, _ := root.ReadFile(dir + "stat")
		// pid (comm) S ppid ...
		open, close := strings.IndexByte(string(stat), '('), strings.LastIndexByte(string(stat), ')')
		if open < 0 || close < open {
			continue
		}
		p := proc{pid: pid, comm: string(stat[open+1 : close])}
		f := strings.Fields(string(stat[close+1:]))
		if len(f) < 21 {
			continue
		}
		p.stat = f[0]
		p.ppid, _ = strconv.Atoi(f[1])
		vsize, _ := strconv.Atoi(f[20])
		p.vsz = vsize / 1024
		if p.vsz == 0 {
			p.stat += "W"
		}
		if nice, _ := strconv.Atoi(f[16]); nice < 0 {
			p.stat += "<"
		}
		cmdline, _ := root.ReadFile(dir + "cmdline")
		p.cmd = strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " "))
		if p.cmd == "" {
			p.cmd = "[" + p.comm + "]"
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pid < out[j].pid })
	return out
}

// meminfo reads /proc/meminfo, in kB.
func meminfo(e *shell.Env) map[string]int64 {
	data, _ := e.FS.AsRoot().ReadFile("/proc/meminfo")
	m := map[string]int64{}
	for _, l := range splitLines(string(data)) {
		k, v, ok := strings.Cut(l, ":")
		if ok {
			m[k], _ = strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		}
	}
	return m
}

func loadavg(e *shell.Env) string {
	data, _ := e.FS.AsRoot().ReadFile("/proc/loadavg")
	return strings.TrimSpace(string(data))
}

func cmdPs(e *shell.Env) int {
	e.Print("  PID USER       VSZ STAT COMMAND\n")
	for _, p := range processes(e) {
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
		procs := processes(e)
		m := meminfo(e)
		e.Printf("Mem: %dK used, %dK free, %dK shrd, %dK buff, %dK cached\n",
			m["MemTotal"]-m["MemFree"], m["MemFree"], m["Shmem"], m["Buffers"], m["Cached"])
		e.Print("CPU:   2% usr   3% sys   0% nic  94% idle   0% io   0% irq   0% sirq\n")
		e.Printf("Load average: %s\n", loadavg(e))
		e.Print("  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND\n")
		for _, p := range procs {
			cpu := 0
			if p.comm == "ipcam" {
				cpu = 4
			}
			e.Printf("%5d %5d root     %-4s %5d %3d%% %3d%% %s\n", p.pid, p.ppid, p.stat, p.vsz, int64(p.vsz)*100/m["MemTotal"], cpu, p.cmd)
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
	sig := 15
	if strings.HasPrefix(args[0], "-") && len(args[0]) > 1 {
		name := args[0][1:]
		if name == "s" && len(args) > 1 {
			args, name = args[1:], args[1][0:]
		}
		n, ok := signalNumber(name)
		if !ok {
			fmt.Fprintf(e.Stderr, "%sinvalid signal: %s\n", prefix, name)
			return 1
		}
		sig = n
		args = args[1:]
	}
	status := 0
	for _, a := range args {
		if _, err := strconv.Atoi(a); err != nil && !strings.HasPrefix(a, "%") {
			fmt.Fprintf(e.Stderr, "%sillegal number: %s\n", prefix, a)
			status = 1
			continue
		}
		if !e.Kill(a, sig) {
			if strings.HasPrefix(a, "%") {
				fmt.Fprintf(e.Stderr, "%s%s: no such job\n", prefix, a)
			} else {
				fmt.Fprintf(e.Stderr, "%scan't kill pid %s: No such process\n", prefix, a)
			}
			status = 1
		}
	}
	return status
}

// signalNumber reads a signal given as 9, KILL or SIGKILL.
func signalNumber(s string) (int, bool) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, n >= 0 && n <= len(signals)
	}
	s = strings.TrimPrefix(strings.ToUpper(s), "SIG")
	for i, name := range signals {
		if name == s {
			return i + 1, true
		}
	}
	return 0, false
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
			if p.comm == name && p.pid != e.PID {
				found = true
				e.Kill(strconv.Itoa(p.pid), 15)
			}
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

package shell

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Background jobs. A job (cmd &) runs at once, to completion, but with
// its sleeps fast-forwarded: its side effects happen and its output shows
// up, while the time it would take decides how long it stays "Running" in
// jobs and ps, and how long wait waits for it.

type job struct {
	num, pid int
	cmd      string
	end      time.Time // when it finishes
	status   int
	killed   bool
}

func (j *job) running(now time.Time) bool { return !j.killed && now.Before(j.end) }

// sleep is how every command sleeps: really (or on the test clock), or,
// in a background job, by just adding up the time.
func (s *Shell) sleep(ctx context.Context, d time.Duration) bool {
	if s.ffwd != nil {
		*s.ffwd += d
		return ctx.Err() == nil
	}
	return s.cfg.Sleep(ctx, d)
}

func (s *Shell) startJob(ctx context.Context, pl *pipeline, std stdio) {
	if !s.fork() {
		return
	}
	num := 1
	for s.jobNum(num) != nil {
		num++
	}
	pid := s.allocPID()
	j := &job{num: num, pid: pid, cmd: pipelineText(pl)}
	s.jobList = append(s.jobList, j)
	s.lastBg = pid
	if s.cfg.Mode == LoginShell && s.depth == 0 {
		fmt.Fprintf(std.err, "[%d] %d\n", num, pid)
	}
	args := []string{"-sh"}
	if len(pl.cmds) == 1 && len(pl.cmds[0].words) > 0 {
		args = rawArgs(pl.cmds[0].words)
	}

	var elapsed time.Duration
	saved := s.ffwd
	s.ffwd = &elapsed
	j.status, _ = s.nest(true, nil, func() int {
		return s.runPipeline(ctx, pl, stdio{strings.NewReader(""), std.out, std.err})
	})
	s.ffwd = saved
	j.end = s.now().Add(elapsed)
	if elapsed > 0 {
		s.spawn(pid, args, "/bin/busybox", 'S')
		if p, ok := s.kernel.Get(pid); ok {
			p.Until = j.end
			s.kernel.Add(p)
		}
	}
}

func (s *Shell) jobNum(n int) *job {
	for _, j := range s.jobList {
		if j.num == n {
			return j
		}
	}
	return nil
}

// findJob resolves %N, %%, %+ or a pid.
func (s *Shell) findJob(spec string) *job {
	if spec == "%%" || spec == "%+" || spec == "%" {
		if len(s.jobList) > 0 {
			return s.jobList[len(s.jobList)-1]
		}
		return nil
	}
	if n, ok := strings.CutPrefix(spec, "%"); ok {
		num, _ := strconv.Atoi(n)
		return s.jobNum(num)
	}
	pid, _ := strconv.Atoi(spec)
	for _, j := range s.jobList {
		if j.pid == pid {
			return j
		}
	}
	return nil
}

// reapJobs forgets jobs that ended, and their processes. With report, it
// prints the "[1]+  Done" lines an interactive ash shows before a prompt.
func (s *Shell) reapJobs(report bool) string {
	now := s.now()
	var b strings.Builder
	var keep []*job
	for i, j := range s.jobList {
		if j.running(now) {
			keep = append(keep, j)
			continue
		}
		s.reap(j.pid)
		if report {
			b.WriteString(jobLine(j, i == len(s.jobList)-1, now))
		}
	}
	s.jobList = keep
	return b.String()
}

// jobLine formats a job the way ash's jobs does.
func jobLine(j *job, current bool, now time.Time) string {
	mark := " "
	if current {
		mark = "+"
	}
	state := "Running"
	switch {
	case j.killed:
		state = "Terminated"
	case j.running(now):
	case j.status != 0:
		state = fmt.Sprintf("Done(%d)", j.status)
	default:
		state = "Done"
	}
	head := fmt.Sprintf("[%d]%s  %s", j.num, mark, state)
	return fmt.Sprintf("%-33s%s\n", head, j.cmd)
}

// pipelineText is how jobs shows a pipeline.
func pipelineText(pl *pipeline) string {
	var parts []string
	for _, c := range pl.cmds {
		if len(c.words) > 0 {
			parts = append(parts, strings.Join(c.words, " "))
		} else {
			parts = append(parts, "(...)")
		}
	}
	return strings.Join(parts, " | ")
}

func builtinJobs(e *Env) int {
	s := e.sh
	now := s.now()
	for i, j := range s.jobList {
		e.Print(jobLine(j, i == len(s.jobList)-1, now))
	}
	s.reapJobs(false)
	return 0
}

// builtinWait waits for jobs to finish: all of them, or those named.
func builtinWait(e *Env) int {
	s := e.sh
	targets := s.jobList
	if len(e.Args) > 1 {
		targets = nil
		for _, a := range e.Args[1:] {
			j := s.findJob(a)
			if j == nil {
				if strings.HasPrefix(a, "%") {
					sh(e, "wait: %s: no such job", a)
					return 127
				}
				return 127 // not a child of this shell
			}
			targets = append(targets, j)
		}
	}
	status := 0
	for _, j := range targets {
		if d := j.end.Sub(s.now()); j.running(s.now()) && !s.sleep(e.Ctx, d) {
			return 130
		}
		status = j.status
		if j.killed {
			status = 143
		}
	}
	s.reapJobs(false)
	return status
}

// builtinFg waits for a job in the foreground; bg has nothing to do.
func builtinFg(e *Env) int {
	s := e.sh
	spec := "%%"
	if len(e.Args) > 1 {
		spec = e.Args[1]
	}
	j := s.findJob(spec)
	if j == nil {
		sh(e, "%s: %s: no such job", e.Args[0], spec)
		return 2
	}
	if e.Args[0] == "bg" {
		e.Printf("[%d] %s\n", j.num, j.cmd)
		return 0
	}
	e.Printf("%s\n", j.cmd)
	if j.running(s.now()) && !s.sleep(e.Ctx, j.end.Sub(s.now())) {
		j.killed = true
		return 130
	}
	s.reapJobs(false)
	return j.status
}

// Kill delivers sig to pid (or a job spec like %1), as far as the
// simulation goes: jobs stop, killing a session's shell or dropbear ends
// that session (this one or another), and the camera's own processes
// disappear from ps. It returns false if there is no such process.
func (e *Env) Kill(target string, sig int) bool {
	s := e.sh
	if j := s.findJob(target); j != nil && (strings.HasPrefix(target, "%") || j.running(s.now())) {
		if sig != 0 {
			j.killed = true
			s.reap(j.pid)
		}
		return true
	}
	pid, err := strconv.Atoi(target)
	if err != nil {
		return false
	}
	return s.kernel.Signal(pid, sig, s.now())
}

// ---- trap ----

var signalNames = []string{"EXIT", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM",
	"STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS"}

// signal is how the shell takes a signal sent to it with kill, from this
// session or another: a trap runs its action, signals ash ignores are
// ignored, and anything else ends the session.
func (s *Shell) signal(sig int) {
	name := ""
	if sig > 0 && sig < len(signalNames) {
		name = signalNames[sig]
	}
	if traps := s.trapSnap.Load(); traps != nil && name != "KILL" && name != "STOP" {
		if action, ok := (*traps)[name]; ok {
			if action != "" {
				s.pendingSig.Store(int32(sig))
			}
			return
		}
	}
	switch name {
	case "CHLD", "CONT", "WINCH", "URG", "STOP", "TSTP", "TTIN", "TTOU":
		return
	case "TERM", "INT", "QUIT":
		if s.cfg.Mode == LoginShell {
			return // an interactive ash ignores these
		}
	}
	s.hangup(sig)
}

// runPendingTrap runs the action of a trapped signal that arrived.
func (s *Shell) runPendingTrap(ctx context.Context, std stdio) {
	sig := int(s.pendingSig.Swap(0))
	if sig <= 0 || sig >= len(signalNames) {
		return
	}
	if action := s.traps[signalNames[sig]]; action != "" {
		s.execString(ctx, action, std)
	}
}

func signalName(s string) (string, bool) {
	s = strings.TrimPrefix(strings.ToUpper(s), "SIG")
	if n, err := strconv.Atoi(s); err == nil {
		if n >= 0 && n < len(signalNames) {
			return signalNames[n], true
		}
		return "", false
	}
	for _, name := range signalNames {
		if name == s {
			return name, true
		}
	}
	return "", false
}

func builtinTrap(e *Env) int {
	s := e.sh
	args := e.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		names := make([]string, 0, len(s.traps))
		for name := range s.traps {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			e.Printf("trap -- %s %s\n", quote(s.traps[name]), name)
		}
		return 0
	}
	action := args[0]
	sigs := args[1:]
	if _, isSig := signalName(action); len(args) == 1 || (isSig && action != "" && !strings.ContainsAny(action, " ;")) && len(sigs) == 0 {
		// trap SIG: reset it.
		sigs, action = args, "-"
	}
	status := 0
	for _, sg := range sigs {
		name, ok := signalName(sg)
		if !ok {
			sh(e, "trap: %s: bad trap", sg)
			status = 1
			continue
		}
		if action == "-" {
			delete(s.traps, name)
		} else {
			s.traps[name] = action
		}
	}
	if !s.inChild() {
		snap := maps.Clone(s.traps)
		s.trapSnap.Store(&snap)
	}
	return status
}

// runExitTrap runs the EXIT trap, once.
func (s *Shell) runExitTrap(ctx context.Context, std stdio) {
	action, ok := s.traps["EXIT"]
	if !ok {
		return
	}
	delete(s.traps, "EXIT")
	exited, leaving, code := s.exited, s.leaving, s.exitCode
	s.exited, s.leaving = false, false
	s.execString(ctx, action, std)
	s.exited, s.leaving, s.exitCode = exited, leaving, code
}

// ---- getopts ----

func builtinGetopts(e *Env) int {
	s := e.sh
	if len(e.Args) < 3 {
		sh(e, "getopts: usage: getopts optstring var [arg]")
		return 2
	}
	spec, name := e.Args[1], e.Args[2]
	args := e.Args[3:]
	if len(e.Args) == 3 {
		args = s.args[min(1, len(s.args)):]
	}
	silent := strings.HasPrefix(spec, ":")
	spec = strings.TrimPrefix(spec, ":")
	ind, _ := strconv.Atoi(s.getVar("OPTIND"))
	ind = max(ind, 1)
	pos, _ := strconv.Atoi(s.vars["\x00optpos"]) // position inside a group like -abc
	done := func() int {
		s.setVar(name, "?")
		delete(s.vars, "OPTARG")
		s.vars["\x00optpos"] = "0"
		return 1
	}
	if ind > len(args) {
		return done()
	}
	arg := args[ind-1]
	if pos == 0 {
		if arg == "--" {
			s.setVar("OPTIND", strconv.Itoa(ind+1))
			return done()
		}
		if len(arg) < 2 || arg[0] != '-' {
			return done()
		}
		pos = 1
	}
	c := arg[pos]
	pos++
	next := func() {
		if pos >= len(arg) {
			ind++
			pos = 0
		}
		s.setVar("OPTIND", strconv.Itoa(ind))
		s.vars["\x00optpos"] = strconv.Itoa(pos)
	}
	i := strings.IndexByte(spec, c)
	if i < 0 || c == ':' {
		if silent {
			s.setVar("OPTARG", string(c))
		} else {
			fmt.Fprintf(e.Stderr, "Illegal option -%c\n", c)
			delete(s.vars, "OPTARG")
		}
		s.setVar(name, "?")
		next()
		return 0
	}
	s.setVar(name, string(c))
	if i+1 < len(spec) && spec[i+1] == ':' {
		switch {
		case pos < len(arg):
			s.setVar("OPTARG", arg[pos:])
			pos = len(arg)
		case ind < len(args):
			s.setVar("OPTARG", args[ind])
			ind++
		default:
			if silent {
				s.setVar(name, ":")
				s.setVar("OPTARG", string(c))
			} else {
				fmt.Fprintf(e.Stderr, "No arg for -%c option\n", c)
				s.setVar(name, "?")
			}
		}
	} else {
		delete(s.vars, "OPTARG")
	}
	next()
	return 0
}

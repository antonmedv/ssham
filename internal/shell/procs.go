package shell

import (
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/vfs"
)

// The session's processes: the dropbear child serving the connection, the
// shell, and whatever runs in it. /proc is kept in step with them, so ps,
// top and /proc/<pid> always agree.

func (s *Shell) startProcs() {
	if s.cfg.Term != "" {
		// The session's terminal.
		n := s.kernel.OpenPTY()
		s.pty = n
		s.tty = "/dev/pts/" + strconv.Itoa(n)
		s.fs.Put(s.tty, &vfs.Node{Mode: fs.ModeDevice | fs.ModeCharDevice | 0o620, Owner: s.user.Name, Group: "root",
			ModTime: s.now(), Device: vfs.DevOther, Major: 136, Minor: n})
	}
	up := s.now().Sub(s.kernel.Booted())
	dropbear := s.pid - 1
	s.addProc(rootfs.Proc{PID: dropbear, PPID: 124, Comm: "dropbear", Cmdline: []string{"/usr/sbin/dropbear", "-R", "-p", "22"},
		Exe: "/usr/sbin/dropbear", VSZ: 1088, RSS: 524, Threads: 1, Started: up})
	s.addProc(rootfs.Proc{PID: s.pid, PPID: dropbear, Comm: "sh", Cmdline: []string{"-sh"},
		Exe: "/bin/busybox", VSZ: 1244, RSS: 560, Threads: 1, Started: up, TTY: s.tty})
	s.kernel.Handle(dropbear, s.hangup)
	s.kernel.Handle(s.pid, s.signal)
}

// hangup ends the session: its shell or dropbear was killed.
func (s *Shell) hangup(sig int) {
	s.signaled.Store(int32(sig))
	s.Interrupt()
	if s.cfg.Hangup != nil {
		s.cfg.Hangup()
	}
}

// Close takes the session's processes and terminal off the camera.
func (s *Shell) Close() {
	for pid := range s.mine {
		s.kernel.Remove(pid)
	}
	if s.tty != "" {
		s.fs.Delete(s.tty)
		s.kernel.ClosePTY(s.pty)
	}
}

func (s *Shell) addProc(p rootfs.Proc) {
	s.kernel.Add(p)
	s.mine[p.PID] = true
}

// spawn adds a child of the current shell running args.
func (s *Shell) spawn(pid int, args []string, exe string, state byte) {
	comm := path.Base(args[0])
	if len(comm) > 15 {
		comm = comm[:15]
	}
	s.addProc(rootfs.Proc{PID: pid, PPID: s.pid, Comm: comm, Cmdline: slices.Clone(args), Exe: exe,
		State: state, VSZ: 1240, RSS: 448, Threads: 1, Started: s.now().Sub(s.kernel.Booted()),
		TTY: s.tty, Environ: s.environ(true)})
	// Rewrite it in /proc if a pipeline stage registered it earlier.
	s.fs.Delete("/proc/" + strconv.Itoa(pid))
}

func (s *Shell) reap(pid int) {
	s.kernel.Remove(pid)
	delete(s.mine, pid)
}

// syncProc updates /proc, as seen by the process self.
func (s *Shell) syncProc(self int) { s.kernel.Sync(s.fs, s.now(), self) }

// ppid is $PPID: the parent of the current shell process.
func (s *Shell) ppid() int {
	if p, ok := s.kernel.Get(s.pid); ok {
		return p.PPID
	}
	return s.loginPID - 1
}

// rawArgs is a best guess at the argv of a pipeline stage that has not
// started yet, for ps to show while an earlier stage runs.
func rawArgs(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = strings.NewReplacer(`"`, "", `'`, "", `\`, "").Replace(w)
	}
	return out
}

func (s *Shell) errOrTerm() io.Writer {
	if s.errOut != nil {
		return s.errOut
	}
	return s.term
}

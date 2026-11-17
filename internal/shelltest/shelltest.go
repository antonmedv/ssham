// Package shelltest runs fake shell sessions in memory for tests.
//
// Sessions are deterministic: the clock is fixed (sleep advances it instead
// of waiting), randomness is seeded, and every session starts from the same
// disk image. The same command always prints the same output, so tests can
// compare it exactly.
package shelltest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/commands"
	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/shell"
	"github.com/antonmedv/ssham/internal/vfs"
)

// Start is the fixed time sessions begin at.
var Start = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// Host is the fake machine used in tests.
var Host = rootfs.Host{
	Hostname: "ipcam",
	Kernel:   "4.9.37",
	Booted:   time.Date(2026, 10, 3, 7, 42, 0, 0, time.UTC),
}

var (
	baseOnce sync.Once
	base     *vfs.FS
)

func image() *vfs.FS {
	baseOnce.Do(func() {
		f, err := rootfs.Build(Host)
		if err != nil {
			panic(err)
		}
		f.Now = func() time.Time { return Start }
		shell.Install(f, commands.Registry())
		base = f
	})
	return base.Clone()
}

// Session is a shell session running in memory.
type Session struct {
	t     testing.TB
	Shell *shell.Shell
	FS    *vfs.FS
	term  *Terminal
	log   bytes.Buffer
	now   time.Time
	// budget is how much fake time the current command may sleep before
	// it is interrupted, as if the user pressed Ctrl+C. It stops commands
	// that wait forever (ping, top, nc -l) from hanging tests.
	budget time.Duration
}

// SleepBudget is how long a command may sleep before tests interrupt it.
const SleepBudget = 10 * time.Minute

// Option customizes a test session.
type Option func(*shell.Config)

// RealSleep makes sleep actually wait, for tests of interrupting commands.
func RealSleep() Option {
	return func(c *shell.Config) { c.Sleep = nil }
}

// WithCommands adds extra commands to the session, for testing the shell
// with commands that misbehave.
func WithCommands(cmds ...shell.Command) Option {
	return func(c *shell.Config) {
		r := shell.NewRegistry()
		for _, name := range commands.Registry().Names() {
			if cmd, _ := commands.Registry().Lookup(name); cmd.Name == name {
				r.Add(*cmd)
			}
		}
		r.Add(cmds...)
		shell.Install(c.FS, r)
		c.Commands = r
	}
}

// New starts a session logged in as user.
func New(t testing.TB, user string, opts ...Option) *Session {
	s := &Session{t: t, FS: image(), now: Start, term: &Terminal{}}
	cfg := shell.Config{
		Host:     Host,
		User:     user,
		FS:       s.FS,
		Commands: commands.Registry(),
		Log:      audit.New(&s.log).Session("test", "203.0.113.9:50000"),
		ClientIP: "203.0.113.9",
		Started:  Start,
		Clock:    func() time.Time { return s.now },
		Rand:     rand.New(rand.NewPCG(1, 2)),
		Sleep: func(ctx context.Context, d time.Duration) bool {
			if d > s.budget {
				s.now = s.now.Add(s.budget)
				s.budget = 0
				return false
			}
			s.now = s.now.Add(d)
			s.budget -= d
			return ctx.Err() == nil
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	s.Shell = shell.New(cfg, s.term)
	return s
}

// Run executes a command line as if typed at the prompt and returns what
// the terminal showed (stdout and stderr interleaved) and the exit status.
// input lines answer prompts the command shows, such as sudo's password.
func (s *Session) Run(line string, input ...string) (output string, status int) {
	s.term.out.Reset()
	s.term.input = input
	s.budget = SleepBudget
	status = s.Shell.Exec(context.Background(), line)
	return s.term.out.String(), status
}

// Repl runs the interactive loop, typing each input line at the prompt,
// until the input runs out or the user exits. It returns everything the
// terminal showed, prompts included, and the exit status.
func (s *Session) Repl(input ...string) (output string, status int) {
	s.term.out.Reset()
	s.term.input = input
	s.budget = SleepBudget
	status = s.Shell.Run(context.Background())
	return s.term.out.String(), status
}

// Exec runs a command line without a terminal, as `ssh host 'cmd'` does,
// and returns its combined output and exit status.
func (s *Session) Exec(line string) (output string, status int) {
	s.budget = SleepBudget
	return s.Shell.Capture(context.Background(), line, strings.NewReader(""))
}

// Event is one audit log entry.
type Event map[string]any

// Events returns the audit events with the given name ("" for all).
func (s *Session) Events(name string) []Event {
	var out []Event
	dec := json.NewDecoder(bytes.NewReader(s.log.Bytes()))
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			break
		}
		if name == "" || ev["msg"] == name {
			out = append(out, ev)
		}
	}
	return out
}

// Terminal is a fake terminal: it records output and answers prompts
// from a list of input lines, echoing them like a real terminal would.
type Terminal struct {
	out   bytes.Buffer
	input []string
}

func (t *Terminal) Write(p []byte) (int, error) { return t.out.Write(p) }

func (t *Terminal) ReadLine(prompt string, echo bool) (string, error) {
	t.out.WriteString(prompt)
	if len(t.input) == 0 {
		t.out.WriteString("\n")
		return "", io.EOF
	}
	line := t.input[0]
	t.input = t.input[1:]
	if echo {
		t.out.WriteString(line)
	}
	t.out.WriteString("\n")
	return line, nil
}

// clean makes terminal output readable in a text file.
func clean(s string) string {
	s = strings.ReplaceAll(s, "\x1b", "^[")
	return s
}

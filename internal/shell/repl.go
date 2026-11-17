package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
)

// Run is the interactive read-eval loop. It returns when the attacker
// exits, the input ends, or ctx is cancelled.
func (s *Shell) Run(ctx context.Context) int {
	for !s.exited && ctx.Err() == nil {
		line, err := s.term.ReadLine(s.Prompt(), true)
		if errors.Is(err, ErrInterrupt) {
			s.status = 130
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.log.Event(audit.Input, "line", "^D")
				if s.popIdentity() {
					s.write("exit\n")
					continue
				}
				if s.cfg.Term != "" {
					s.write("logout\n")
				}
			}
			break
		}
		s.log.Event(audit.Input, "line", line)
		s.addHistory(line)
		s.Exec(ctx, line)
	}
	return s.exitCode
}

// Prompt renders PS1 the way Ubuntu's default .bashrc does.
func (s *Shell) Prompt() string {
	sigil := "$"
	if s.user.IsRoot() {
		sigil = "#"
	}
	host, _, _ := strings.Cut(s.cfg.Host.Hostname, ".")
	if strings.Contains(s.cfg.Term, "color") || strings.HasPrefix(s.cfg.Term, "xterm") {
		return fmt.Sprintf("\x1b[01;32m%s@%s\x1b[00m:\x1b[01;34m%s\x1b[00m%s ", s.user.Name, host, s.prettyCwd(), sigil)
	}
	return fmt.Sprintf("%s@%s:%s%s ", s.user.Name, host, s.prettyCwd(), sigil)
}

// prettyCwd abbreviates the home directory as ~.
func (s *Shell) prettyCwd() string {
	home := s.user.Home
	switch {
	case s.cwd == home:
		return "~"
	case strings.HasPrefix(s.cwd, home+"/"):
		return "~" + s.cwd[len(home):]
	}
	return s.cwd
}

func (s *Shell) addHistory(line string) {
	if strings.TrimSpace(line) == "" || strings.HasPrefix(line, " ") {
		return
	}
	if n := len(s.history); n > 0 && s.history[n-1] == line {
		return
	}
	s.history = append(s.history, line)
	if len(s.history) > maxHistory {
		s.history = s.history[1:]
	}
}

// History returns the command history, oldest first. It must only be called
// while the shell is waiting for input.
func (s *Shell) History() []string { return s.history }

func (s *Shell) write(str string) { _, _ = io.WriteString(s.term, str) }

// Motd returns the login banner Ubuntu shows on an interactive login.
func (s *Shell) Motd() string {
	h := s.cfg.Host
	started := s.cfg.Started
	last := started.Add(-26*time.Hour - 17*time.Minute)
	return "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux " + h.Kernel + " x86_64)\n\n" +
		" * Documentation:  https://help.ubuntu.com\n" +
		" * Management:     https://landscape.canonical.com\n" +
		" * Support:        https://ubuntu.com/pro\n\n" +
		" System information as of " + started.UTC().Format("Mon Jan _2 15:04:05 UTC 2006") + "\n\n" +
		"  System load:  0.08              Processes:             112\n" +
		"  Usage of /:   6.3% of 77.35GB   Users logged in:       0\n" +
		"  Memory usage: 24%               IPv4 address for ens5: 10.0.2.15\n" +
		"  Swap usage:   0%\n\n" +
		"Expanded Security Maintenance for Applications is not enabled.\n\n" +
		"3 updates can be applied immediately.\n" +
		"To see these additional updates run: apt list --upgradable\n\n" +
		"Enable ESM Apps to receive additional future security updates.\n" +
		"See https://ubuntu.com/esm or run: sudo pro status\n\n\n" +
		"Last login: " + last.Format("Mon Jan _2 15:04:05 2006") + " from 10.0.2.2\n"
}

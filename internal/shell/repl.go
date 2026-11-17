package shell

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/rootfs"
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
				// Ctrl+D leaves a nested shell, or logs out. ash says
				// nothing either way.
				s.log.Event(audit.Input, "line", "^D")
				if s.popIdentity() {
					continue
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

// Prompt renders ash's default PS1, '\w \$ ': the working directory
// (~ for home) and # for root.
func (s *Shell) Prompt() string {
	sigil := "$"
	if s.user.IsRoot() {
		sigil = "#"
	}
	return s.prettyCwd() + " " + sigil + " "
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

// Motd returns what an interactive login shows: ash's banner.
func (s *Shell) Motd() string {
	return "\n\n" + rootfs.BusyBox + " built-in shell (ash)\n\n"
}

package shell

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/rootfs"
)

// Run is the interactive read-eval loop. It returns when the attacker
// exits, the input ends, or ctx is cancelled.
func (s *Shell) Run(ctx context.Context) int {
	defer s.runExitTrap(ctx, stdio{strings.NewReader(""), s.term, s.term})
	for !s.exited && ctx.Err() == nil && s.signaled.Load() == 0 {
		if s.pendingSig.Load() != 0 {
			s.runPendingTrap(ctx, stdio{strings.NewReader(""), s.term, s.term})
		}
		if s.cfg.Mode == LoginShell {
			s.write(s.reapJobs(true))
		}
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
		line, err = s.ReadCommand(line)
		if errors.Is(err, ErrInterrupt) {
			s.status = 130
			continue
		}
		s.log.Event(audit.Input, "line", line)
		s.addHistory(line)
		s.Exec(ctx, line)
	}
	return s.exitCode
}

// ReadCommand completes a command whose first line is first: while it is
// incomplete (an open quote, an if without fi, a here-document, a line
// ending in &&), it reads more lines at the $PS2 prompt. At the end of
// input it returns what it has, which then fails to parse as in ash.
func (s *Shell) ReadCommand(first string) (string, error) {
	line := first
	for {
		_, err := parseInput(line, false)
		var se *SyntaxError
		if !errors.As(err, &se) || !se.Incomplete() {
			return line, nil
		}
		more, err := s.term.ReadLine(s.renderPrompt(s.getVar("PS2")), true)
		if errors.Is(err, ErrInterrupt) {
			return "", err
		}
		if err != nil {
			return line, nil
		}
		line += "\n" + more
	}
}

// Prompt renders $PS1, by default ash's '\w \$ ': the working directory
// (~ for home) and # for root.
func (s *Shell) Prompt() string { return s.renderPrompt(s.getVar("PS1")) }

// renderPrompt expands the backslash escapes ash's fancy prompt knows.
func (s *Shell) renderPrompt(ps string) string {
	var b strings.Builder
	for i := 0; i < len(ps); i++ {
		if ps[i] != '\\' || i+1 == len(ps) {
			b.WriteByte(ps[i])
			continue
		}
		i++
		switch ps[i] {
		case 'w':
			b.WriteString(s.prettyCwd())
		case 'W':
			b.WriteString(path.Base(s.prettyCwd()))
		case 'u':
			b.WriteString(s.user.Name)
		case 'h', 'H':
			b.WriteString(s.cfg.Host.Hostname)
		case '$':
			if s.user.IsRoot() {
				b.WriteByte('#')
			} else {
				b.WriteByte('$')
			}
		case 'n':
			b.WriteByte('\n')
		case 'e':
			b.WriteByte(0x1b)
		case '[', ']':
		default:
			b.WriteByte('\\')
			b.WriteByte(ps[i])
		}
	}
	return b.String()
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

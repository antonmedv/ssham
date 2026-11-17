// Package tui renders the fake shell over SSH with Bubble Tea. The shell runs
// in its own goroutine and talks to the Bubble Tea program through Term.
package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"

	"github.com/antonmedv/ssham/internal/shell"
)

// Messages sent from the shell goroutine to the model.
type (
	readRequestMsg struct {
		prompt string
		echo   bool
		reply  chan readResult
	}
	partialMsg struct{ text string }
	doneMsg    struct{}
)

type readResult struct {
	line string
	err  error
}

// Term implements shell.Terminal on top of a Bubble Tea program. Complete
// lines of output are printed above the program (so they land in the
// terminal's normal scrollback); the unfinished last line and the input
// line are rendered by the model's view.
//
// All printing happens on the shell goroutine through Program.Send, which
// keeps output strictly ordered and never blocks after the program exits.
type Term struct {
	ctx   context.Context
	prog  *tea.Program
	width atomic.Int64

	mu      sync.Mutex
	partial string
}

// NewTerm returns a Term. Attach must be called before the shell runs.
func NewTerm(ctx context.Context, width int) *Term {
	t := &Term{ctx: ctx}
	t.width.Store(int64(width))
	return t
}

// Attach connects the Term to its program.
func (t *Term) Attach(p *tea.Program) { t.prog = p }

// Width reports the terminal width in columns.
func (t *Term) Width() int { return int(t.width.Load()) }

func (t *Term) setWidth(w int) { t.width.Store(int64(w)) }

const clearSeq = "\x1b[H\x1b[2J"

// Write implements io.Writer.
func (t *Term) Write(p []byte) (int, error) {
	if t.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.partial + string(p)
	s = strings.ReplaceAll(s, "\r\n", "\n")

	// A clear-screen sequence splits the output: print what came before,
	// clear, then continue with what follows. BusyBox's clear sends
	// ESC[H ESC[J; others send ESC[H ESC[2J.
	s = strings.ReplaceAll(s, "\x1b[H\x1b[J", clearSeq)
	for {
		i := strings.Index(s, clearSeq)
		if i < 0 {
			break
		}
		before := s[:i]
		s = strings.TrimPrefix(s[i+len(clearSeq):], "\x1b[3J")
		if before != "" {
			t.printLines(strings.TrimSuffix(before, "\n"))
		}
		t.clear()
	}

	if nl := strings.LastIndexByte(s, '\n'); nl >= 0 {
		t.printLines(s[:nl])
		s = s[nl+1:]
	}
	if s != t.partial {
		t.partial = s
		t.prog.Send(partialMsg{text: expandTabs(s)})
	}
	return len(p), nil
}

func (t *Term) printLines(s string) {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = expandTabs(strings.TrimRight(l, "\r"))
	}
	t.prog.Send(tea.Println(strings.Join(lines, "\n"))())
}

// clear wipes the whole terminal. The renderer's own ClearScreen only
// erases the program's region in inline mode, so the raw sequence goes out
// first and the renderer then redraws from the top-left corner.
func (t *Term) clear() {
	t.prog.Send(tea.Raw(clearSeq + "\x1b[3J")())
	t.prog.Send(tea.ClearScreen())
}

// ReadLine implements shell.Terminal.
func (t *Term) ReadLine(prompt string, echo bool) (string, error) {
	t.mu.Lock()
	full := t.partial + prompt
	t.partial = ""
	t.mu.Unlock()

	reply := make(chan readResult, 1)
	t.prog.Send(readRequestMsg{prompt: expandTabs(full), echo: echo, reply: reply})
	var res readResult
	select {
	case res = <-reply:
	case <-t.ctx.Done():
		return "", io.EOF
	}

	shown := ""
	if echo {
		shown = res.line
	}
	echoed := expandTabs(full + shown)
	if errors.Is(res.err, shell.ErrInterrupt) {
		echoed += "^C"
	}
	t.prog.Send(tea.Println(echoed)())
	return res.line, res.err
}

// Done tells the program the shell has exited.
func (t *Term) Done() { t.prog.Send(doneMsg{}) }

// expandTabs replaces tabs with spaces up to the next 8-column stop, since
// the renderer measures lines without tab expansion. ANSI escape sequences
// do not take up columns.
func expandTabs(s string) string {
	if !strings.Contains(s, "\t") {
		return s
	}
	var b strings.Builder
	col := 0
	inEsc := false
	for _, r := range s {
		switch {
		case inEsc:
			b.WriteRune(r)
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
			continue
		case r == 0x1b:
			inEsc = true
			b.WriteRune(r)
			continue
		case r == '\n':
			col = 0
		case r == '\t':
			n := 8 - col%8
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		default:
			col++
		}
		b.WriteRune(r)
	}
	return b.String()
}

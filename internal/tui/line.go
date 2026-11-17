// Package tui is the attacker's terminal: what BusyBox ash's line editing
// would send over the pty, byte for byte, and nothing else.
package tui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

// Line implements shell.Terminal over an SSH pty. At a prompt it edits
// the line the way BusyBox's lineedit does: it echoes what is typed, moves
// the cursor with backspaces and redraws with \r and ESC[J. While a command
// runs, the pty is in cooked mode, so typed-ahead input is echoed and
// waits for the next prompt. Output gets \n turned into \r\n, as the pty
// does. It never sends anything else: no mode changes, no queries.
type Line struct {
	out   io.Writer
	mu    sync.Mutex // serializes writes
	width atomic.Int64
	log   *audit.SessionLogger

	sh       *shell.Shell
	requests chan request
	keys     chan key
	closed   chan struct{}

	editor  *Editor
	lastTab bool
	pending []key // typed while a command ran, for the next prompt
}

type request struct {
	prompt string
	echo   bool
	reply  chan result
}

type result struct {
	line string
	err  error
}

// New returns a terminal writing to out. Attach and Run must be called
// before the shell starts.
func New(out io.Writer, width int, log *audit.SessionLogger) *Line {
	t := &Line{out: out, log: log, requests: make(chan request), keys: make(chan key, 64), closed: make(chan struct{}), editor: NewEditor()}
	t.SetWidth(width)
	return t
}

// Attach gives the terminal its shell, for completion, history and Ctrl+C.
func (t *Line) Attach(sh *shell.Shell) { t.sh = sh }

// SetWidth sets the terminal width in columns.
func (t *Line) SetWidth(w int) {
	if w <= 0 {
		w = 80
	}
	t.width.Store(int64(w))
}

// Width reports the terminal width in columns.
func (t *Line) Width() int { return int(t.width.Load()) }

// Write sends output, with \n made \r\n.
func (t *Line) Write(p []byte) (int, error) {
	t.write(string(p))
	return len(p), nil
}

func (t *Line) write(s string) {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
	t.mu.Lock()
	defer t.mu.Unlock()
	_, _ = io.WriteString(t.out, s)
}

// ReadLine implements shell.Terminal.
func (t *Line) ReadLine(prompt string, echo bool) (string, error) {
	req := request{prompt: prompt, echo: echo, reply: make(chan result, 1)}
	select {
	case t.requests <- req:
	case <-t.closed:
		return "", io.EOF
	}
	select {
	case r := <-req.reply:
		return r.line, r.err
	case <-t.closed:
		return "", io.EOF
	}
}

// Run reads the attacker's keystrokes from in until it ends or ctx is
// done, editing lines for ReadLine and echoing type-ahead in between.
func (t *Line) Run(ctx context.Context, in io.Reader) {
	defer close(t.closed)
	go decodeKeys(in, t.keys)
	var req *request
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-t.requests:
			req = &r
			t.write(r.prompt)
			t.editor.Reset()
			t.lastTab = false
			// Keys typed while the last command ran: lineedit reads them
			// now, and they show again after the prompt.
			for len(t.pending) > 0 && req != nil {
				k := t.pending[0]
				t.pending = t.pending[1:]
				if t.editKey(req, k) {
					req = nil
				}
			}
		case k, ok := <-t.keys:
			if !ok {
				if req != nil {
					req.reply <- result{err: io.EOF}
				}
				return
			}
			if req == nil {
				t.cookedKey(k)
				continue
			}
			if done := t.editKey(req, k); done {
				req = nil
			}
		}
	}
}

// cookedKey handles a key while a command runs. The pty is in cooked
// mode: it echoes the key (control keys as ^X, ESC as ^[), keeps it for
// lineedit to read at the next prompt, and Ctrl+C interrupts the command
// and drops what was typed.
func (t *Line) cookedKey(k key) {
	switch k.name {
	case "ctrl+c":
		t.write("^C")
		t.pending = nil
		if t.log != nil {
			t.log.Event(audit.Input, "line", "^C")
		}
		if t.sh != nil {
			t.sh.Interrupt()
		}
		return
	case "backspace":
		if n := len(t.pending); n > 0 && t.pending[n-1].name == "" {
			t.pending = t.pending[:n-1]
			t.write("\b \b")
		}
		return
	}
	t.pending = append(t.pending, k)
	t.write(caret(k))
}

// caret is how a tty with ECHOCTL echoes a key.
func caret(k key) string {
	switch {
	case k.name == "":
		return k.text
	case k.name == "enter":
		return "\n"
	case k.name == "tab":
		return "\t"
	case strings.HasPrefix(k.name, "ctrl+") && len(k.name) == 6:
		return "^" + strings.ToUpper(k.name[5:])
	}
	if seq, ok := keySeqs[k.name]; ok {
		return "^[" + seq[1:]
	}
	return "^["
}

// keySeqs are the bytes a terminal sends for named keys.
var keySeqs = map[string]string{
	"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
	"home": "\x1b[H", "end": "\x1b[F", "delete": "\x1b[3~",
}

// editKey handles a key at a prompt. It reports whether the line is done.
func (t *Line) editKey(req *request, k key) bool {
	ed := t.editor
	before := ed.cursor
	switch k.name {
	case "enter":
		t.moveTo(len(ed.text))
		t.write("\n")
		req.reply <- result{line: ed.String()}
		return true
	case "ctrl+c":
		t.write("^C\n")
		req.reply <- result{err: shell.ErrInterrupt}
		return true
	case "ctrl+d":
		if ed.Empty() {
			req.reply <- result{err: io.EOF}
			return true
		}
		if ed.cursor < len(ed.text) {
			ed.deleteChar()
			t.redrawFrom(before, ed.cursor)
		}
		return false
	case "tab":
		if req.echo {
			t.complete(req)
		}
		t.lastTab = true
		return false
	case "up", "down", "ctrl+p", "ctrl+n":
		if req.echo && t.sh != nil {
			dir := 1
			if k.name == "up" || k.name == "ctrl+p" {
				dir = -1
			}
			ed.History(t.sh.History(), dir)
			t.redraw(req, before)
		}
	case "ctrl+l":
		t.write("\x1b[H\x1b[J")
		t.redraw(req, -1)
	case "":
		ed.Insert(k.text)
		if req.echo {
			t.write(k.text)
			if rest := string(ed.text[ed.cursor:]); rest != "" {
				t.write(rest)
				t.back(len(ed.text) - ed.cursor)
			}
		}
	default:
		text := ed.String()
		if !ed.Key(k.name) {
			return false
		}
		if req.echo {
			if text == ed.String() {
				t.moveCursor(before, ed.cursor)
			} else if k.name == "delete" {
				t.redrawFrom(ed.cursor, ed.cursor)
			} else if k.name == "backspace" || k.name == "ctrl+h" {
				t.back(before - ed.cursor)
				t.redrawFrom(ed.cursor, ed.cursor)
			} else {
				t.redraw(req, before)
			}
		}
	}
	t.lastTab = false
	return false
}

// back moves the cursor n columns left, as lineedit's input_backward does.
func (t *Line) back(n int) {
	switch {
	case n <= 0:
	case n <= 4:
		t.write(strings.Repeat("\b", n))
	default:
		t.write(fmt.Sprintf("\x1b[%dD", n))
	}
}

// moveCursor moves from column from to to within the line, the way
// lineedit does: back with \b, forward by printing the characters.
func (t *Line) moveCursor(from, to int) {
	if to < from {
		t.back(from - to)
	} else if to > from {
		t.write(string(t.editor.text[from:to]))
	}
}

func (t *Line) moveTo(pos int) { t.moveCursor(t.editor.cursor, pos) }

// redrawFrom reprints the line from the cursor on, blanks the character
// that went away, and puts the cursor back.
func (t *Line) redrawFrom(cursorWas, cursor int) {
	rest := string(t.editor.text[cursor:])
	t.write(rest + " ")
	t.back(utf8.RuneCountInString(rest) + 1)
}

// redraw reprints the prompt and line from the start of the row, as
// lineedit's redraw: \r, prompt, line, ESC[J, then the cursor back.
func (t *Line) redraw(req *request, _ int) {
	shown := t.editor.String()
	if !req.echo {
		shown = ""
	}
	t.write("\r" + lastLine(req.prompt) + shown + "\x1b[J")
	if req.echo {
		t.back(len(t.editor.text) - t.editor.cursor)
	}
}

func lastLine(s string) string { return s[strings.LastIndexByte(s, '\n')+1:] }

// complete handles Tab like lineedit: a single match is completed; with
// several, the common prefix is, or a beep, and a second Tab lists them.
func (t *Line) complete(req *request) {
	if t.sh == nil {
		return
	}
	ed := t.editor
	word, cands := t.sh.Complete(ed.BeforeCursor())
	switch {
	case len(cands) == 0:
		t.write("\a")
		return
	case len(cands) == 1:
		c := cands[0]
		if !strings.HasSuffix(c, "/") {
			c += " "
		}
		ed.ReplaceBeforeCursor(word, c)
		t.redraw(req, 0)
		return
	}
	if p := commonPrefix(cands); len(p) > len(word) {
		ed.ReplaceBeforeCursor(word, p)
		t.redraw(req, 0)
		return
	}
	if !t.lastTab {
		t.write("\a")
		return
	}
	names := make([]string, len(cands))
	for i, c := range cands {
		dir := strings.HasSuffix(c, "/")
		c = strings.TrimSuffix(c, "/")
		c = c[strings.LastIndexByte(c, '/')+1:]
		if dir {
			c += "/"
		}
		names[i] = c
	}
	t.moveTo(len(ed.text))
	t.write("\n" + layout(names, t.Width()) + "\n")
	t.write(req.prompt + ed.String())
	t.back(len(ed.text) - ed.cursor)
}

func commonPrefix(ss []string) string {
	p := ss[0]
	for _, s := range ss[1:] {
		for !strings.HasPrefix(s, p) {
			p = p[:len(p)-1]
		}
	}
	return p
}

// layout arranges names in columns across the given width, as lineedit
// lists completions.
func layout(names []string, width int) string {
	colW := 0
	for _, n := range names {
		colW = max(colW, len(n)+2)
	}
	cols := max(1, width/colW)
	rows := (len(names) + cols - 1) / cols
	var b strings.Builder
	for r := 0; r < rows; r++ {
		for c := 0; c < cols; c++ {
			i := c*rows + r
			if i >= len(names) {
				continue
			}
			b.WriteString(names[i])
			if c < cols-1 && i+rows < len(names) {
				b.WriteString(strings.Repeat(" ", colW-len(names[i])))
			}
		}
		if r < rows-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// ---- input ----

// key is one keystroke: a named key, or text to insert (name "").
type key struct {
	name string
	text string
}

// decodeKeys turns the bytes a terminal sends into keys. A lone ESC is
// told apart from the start of a sequence by a short wait, as lineedit
// does.
func decodeKeys(in io.Reader, out chan<- key) {
	defer close(out)
	bytesCh := make(chan byte, 256)
	go func() {
		defer close(bytesCh)
		buf := make([]byte, 256)
		for {
			n, err := in.Read(buf)
			for _, b := range buf[:n] {
				bytesCh <- b
			}
			if err != nil {
				return
			}
		}
	}()
	next := func(wait time.Duration) (byte, bool) {
		if wait == 0 {
			b, ok := <-bytesCh
			return b, ok
		}
		select {
		case b, ok := <-bytesCh:
			return b, ok
		case <-time.After(wait):
			return 0, false
		}
	}
	var lastCR bool
	for {
		b, ok := next(0)
		if !ok {
			return
		}
		cr := false
		switch {
		case b == '\r':
			out <- key{name: "enter"}
			cr = true
		case b == '\n':
			if !lastCR {
				out <- key{name: "enter"}
			}
		case b == 0x7f || b == 0x08:
			out <- key{name: "backspace"}
		case b == '\t':
			out <- key{name: "tab"}
		case b == 0x1b:
			out <- escape(next)
		case b < 0x20:
			out <- key{name: "ctrl+" + string(rune('a'+b-1))}
		default:
			// A UTF-8 character.
			buf := []byte{b}
			for !utf8.FullRune(buf) && len(buf) < 4 {
				c, ok := next(50 * time.Millisecond)
				if !ok {
					break
				}
				buf = append(buf, c)
			}
			if r, _ := utf8.DecodeRune(buf); r != utf8.RuneError && r >= 0x20 {
				out <- key{text: string(buf)}
			}
		}
		lastCR = cr
	}
}

// escape decodes what follows ESC.
func escape(next func(time.Duration) (byte, bool)) key {
	b, ok := next(50 * time.Millisecond)
	if !ok {
		return key{name: "esc"}
	}
	if b != '[' && b != 'O' {
		switch b {
		case 'b':
			return key{name: "alt+b"}
		case 'f':
			return key{name: "alt+f"}
		case 0x7f:
			return key{name: "alt+backspace"}
		}
		return key{name: "alt"}
	}
	var seq bytes.Buffer
	for {
		c, ok := next(50 * time.Millisecond)
		if !ok {
			return key{name: "esc"}
		}
		seq.WriteByte(c)
		if c >= 0x40 && c <= 0x7e {
			break
		}
		if seq.Len() > 16 {
			return key{name: "esc"}
		}
	}
	switch seq.String() {
	case "A":
		return key{name: "up"}
	case "B":
		return key{name: "down"}
	case "C":
		return key{name: "right"}
	case "D":
		return key{name: "left"}
	case "H", "1~", "7~":
		return key{name: "home"}
	case "F", "4~", "8~":
		return key{name: "end"}
	case "3~":
		return key{name: "delete"}
	case "1;5D":
		return key{name: "ctrl+left"}
	case "1;5C":
		return key{name: "ctrl+right"}
	}
	return key{name: "esc"}
}

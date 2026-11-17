package tui

import (
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

// Model is the Bubble Tea model for one interactive SSH session. It shows
// the prompt and the line being edited, and hands finished lines to the
// shell. Editing itself is done by Editor.
type Model struct {
	term *Term
	sh   *shell.Shell
	log  *audit.SessionLogger

	width int

	partial string          // output that has no trailing newline yet
	req     *readRequestMsg // the shell is waiting for a line
	editor  *Editor
	queued  []string // complete lines pasted or typed ahead

	lastTab  bool
	quitting bool
}

// NewModel returns a model driving sh through term.
func NewModel(term *Term, sh *shell.Shell, log *audit.SessionLogger, width int) *Model {
	return &Model{term: term, sh: sh, log: log, width: width, editor: NewEditor()}
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.term.setWidth(msg.Width)
	case partialMsg:
		m.partial = msg.text
	case readRequestMsg:
		m.req = &msg
		m.partial = ""
		m.lastTab = false
		if len(m.queued) > 0 {
			line := m.queued[0]
			m.queued = m.queued[1:]
			m.submit(line, nil)
		}
	case doneMsg:
		m.quitting = true
		return m, tea.Quit
	case tea.PasteMsg:
		m.paste(msg.Content)
	case tea.KeyPressMsg:
		tab := msg.String() == "tab"
		cmd := m.key(msg)
		m.lastTab = tab
		return m, cmd
	}
	return m, nil
}

// waiting reports whether the shell is waiting for a line.
func (m *Model) waiting() bool { return m.req != nil }

// submit answers the pending read request and clears the editor.
func (m *Model) submit(line string, err error) {
	if m.req == nil {
		return
	}
	m.req.reply <- readResult{line: line, err: err}
	m.req = nil
	m.editor.Reset()
}

// paste inserts pasted text. Every complete line is entered, as if typed
// followed by Enter; the last fragment stays in the editor.
func (m *Model) paste(s string) {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(s, "\n")
	m.editor.Insert(lines[0])
	if len(lines) == 1 {
		return
	}
	complete := append([]string{m.editor.String()}, lines[1:len(lines)-1]...)
	tail := lines[len(lines)-1]
	if m.waiting() {
		m.submit(complete[0], nil)
		complete = complete[1:]
	}
	m.queued = append(m.queued, complete...)
	m.editor.Reset()
	m.editor.Insert(tail)
}

func (m *Model) key(k tea.KeyPressMsg) tea.Cmd {
	key := k.String()
	switch key {
	case "ctrl+c":
		if !m.waiting() {
			// Interrupt the running command and drop typed-ahead input.
			m.editor.Reset()
			m.queued = nil
			m.log.Event(audit.Input, "line", "^C")
			m.sh.Interrupt()
			return nil
		}
		m.submit(m.editor.String(), shell.ErrInterrupt)
	case "ctrl+d":
		if m.editor.Empty() && m.waiting() {
			m.submit("", io.EOF)
			return nil
		}
		m.editor.Key(key)
	case "enter", "ctrl+m", "ctrl+j":
		if !m.waiting() {
			m.queued = append(m.queued, m.editor.String()) // typeahead
			m.editor.Reset()
			return nil
		}
		m.submit(m.editor.String(), nil)
	case "ctrl+l":
		return tea.Sequence(tea.Raw(clearSeq+"\x1b[3J"), tea.ClearScreen)
	case "up", "ctrl+p", "down", "ctrl+n":
		if m.waiting() && m.req.echo {
			dir := 1
			if key == "up" || key == "ctrl+p" {
				dir = -1
			}
			m.editor.History(m.sh.History(), dir)
		}
	case "tab":
		if m.waiting() && m.req.echo {
			return m.complete()
		}
	default:
		if !m.editor.Key(key) && k.Text != "" {
			m.editor.Insert(k.Text)
		}
	}
	return nil
}

// complete handles Tab like bash: complete a unique match or the common
// prefix; on a second Tab, list the candidates.
func (m *Model) complete() tea.Cmd {
	word, cands := m.sh.Complete(m.editor.BeforeCursor())
	switch {
	case len(cands) == 0:
		return nil
	case len(cands) == 1:
		c := cands[0]
		if !strings.HasSuffix(c, "/") {
			c += " "
		}
		m.editor.ReplaceBeforeCursor(word, c)
		return nil
	}
	if p := commonPrefix(cands); len(p) > len(word) {
		m.editor.ReplaceBeforeCursor(word, p)
		return nil
	}
	if !m.lastTab {
		return nil
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
	return tea.Println(m.req.prompt + m.editor.String() + "\n" + layout(names, m.width))
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

// layout arranges names in columns across the given width.
func layout(names []string, width int) string {
	if width <= 0 {
		width = 80
	}
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

// View implements tea.Model. It shows the unfinished output line (or the
// prompt) followed by the input, wrapped to the terminal width, with the
// cursor where the next character goes.
func (m *Model) View() tea.View {
	if m.quitting {
		return tea.NewView("")
	}
	prefix := m.partial
	shown, before := m.editor.String(), m.editor.BeforeCursor()
	if m.req != nil {
		prefix = m.req.prompt
		if !m.req.echo {
			shown, before = "", "" // password: show nothing
		}
	}
	w := m.width
	if w <= 0 {
		w = 80
	}
	pos := ansi.StringWidth(prefix) + ansi.StringWidth(before)
	wrapped := ansi.Hardwrap(prefix+shown, w, true)
	lines := strings.Count(wrapped, "\n") + 1
	y, x := pos/w, pos%w
	for ; lines <= y; lines++ {
		wrapped += "\n"
	}
	v := tea.NewView(wrapped)
	v.Cursor = tea.NewCursor(x, y)
	return v
}

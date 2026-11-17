package tui

import (
	"io"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

// Model is the Bubble Tea model for one interactive SSH session. It is a
// line editor: it renders the current prompt and input, handles editing
// keys, history and tab completion, and hands finished lines to the shell.
type Model struct {
	term *Term
	sh   *shell.Shell
	log  *audit.SessionLogger

	width int

	partial string          // output that has no trailing newline yet
	req     *readRequestMsg // the shell is waiting for a line
	input   []rune          // current line being edited
	cursor  int             // index into input
	queued  []string        // complete lines pasted or typed ahead

	histIdx  int // position while browsing history; len(history) = new line
	draft    []rune
	lastTab  bool
	quitting bool
}

// NewModel returns a model driving sh through term.
func NewModel(term *Term, sh *shell.Shell, log *audit.SessionLogger, width int) *Model {
	return &Model{term: term, sh: sh, log: log, width: width, histIdx: -1}
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
		m.histIdx = -1
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
		return m, m.key(msg)
	}
	return m, nil
}

// submit answers the pending read request.
func (m *Model) submit(line string, err error) {
	if m.req == nil {
		return
	}
	m.req.reply <- readResult{line: line, err: err}
	m.req = nil
	m.input = nil
	m.cursor = 0
}

func (m *Model) insert(s string) {
	rs := []rune(s)
	in := make([]rune, 0, len(m.input)+len(rs))
	in = append(in, m.input[:m.cursor]...)
	in = append(in, rs...)
	in = append(in, m.input[m.cursor:]...)
	m.input = in
	m.cursor += len(rs)
}

func (m *Model) paste(s string) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	parts := strings.Split(s, "\n")
	m.insert(parts[0])
	if len(parts) == 1 {
		return
	}
	// The first line is complete; any further complete lines are queued
	// like typed-ahead input, and the last fragment stays in the editor.
	first := string(m.input)
	rest := parts[1:]
	m.input = []rune(rest[len(rest)-1])
	m.cursor = len(m.input)
	pending := append([]string{first}, rest[:len(rest)-1]...)
	if m.req != nil {
		tail := m.input
		m.submit(pending[0], nil)
		pending = pending[1:]
		m.input, m.cursor = tail, len(tail)
	}
	m.queued = append(m.queued, pending...)
}

func (m *Model) key(k tea.KeyPressMsg) tea.Cmd {
	waiting := m.req != nil
	tab := false
	defer func() { m.lastTab = tab }()

	switch k.String() {
	case "ctrl+c":
		if !waiting {
			// Interrupt the running command and drop typed-ahead input.
			m.input, m.cursor, m.queued = nil, 0, nil
			m.log.Event("input", "line", "^C")
			m.sh.Interrupt()
			return nil
		}
		m.submit(string(m.input), shell.ErrInterrupt)
		return nil
	case "ctrl+d":
		if len(m.input) == 0 && waiting {
			m.submit("", io.EOF)
			return nil
		}
		if m.cursor < len(m.input) {
			m.input = append(m.input[:m.cursor], m.input[m.cursor+1:]...)
		}
		return nil
	case "enter", "ctrl+m", "ctrl+j":
		line := string(m.input)
		if !waiting {
			m.queued = append(m.queued, line)
			m.input, m.cursor = nil, 0
			return nil
		}
		m.submit(line, nil)
		return nil
	case "backspace", "ctrl+h":
		if m.cursor > 0 {
			m.input = append(m.input[:m.cursor-1], m.input[m.cursor:]...)
			m.cursor--
		}
	case "delete":
		if m.cursor < len(m.input) {
			m.input = append(m.input[:m.cursor], m.input[m.cursor+1:]...)
		}
	case "left", "ctrl+b":
		m.cursor = max(0, m.cursor-1)
	case "right", "ctrl+f":
		m.cursor = min(len(m.input), m.cursor+1)
	case "home", "ctrl+a":
		m.cursor = 0
	case "end", "ctrl+e":
		m.cursor = len(m.input)
	case "alt+b", "ctrl+left":
		m.cursor = wordLeft(m.input, m.cursor)
	case "alt+f", "ctrl+right":
		m.cursor = wordRight(m.input, m.cursor)
	case "ctrl+u":
		m.input = append([]rune{}, m.input[m.cursor:]...)
		m.cursor = 0
	case "ctrl+k":
		m.input = m.input[:m.cursor]
	case "ctrl+w", "alt+backspace":
		start := wordLeft(m.input, m.cursor)
		m.input = append(m.input[:start], m.input[m.cursor:]...)
		m.cursor = start
	case "ctrl+l":
		return tea.Sequence(tea.Raw(clearSeq+"\x1b[3J"), tea.ClearScreen)
	case "up", "ctrl+p":
		if waiting && m.req.echo {
			m.history(-1)
		}
	case "down", "ctrl+n":
		if waiting && m.req.echo {
			m.history(1)
		}
	case "tab":
		tab = true
		if waiting && m.req.echo {
			return m.complete()
		}
	default:
		if k.Text != "" {
			text := strings.Map(func(r rune) rune {
				if unicode.IsControl(r) {
					return -1
				}
				return r
			}, k.Text)
			m.insert(text)
		}
	}
	return nil
}

func (m *Model) history(dir int) {
	h := m.sh.History()
	if m.histIdx < 0 {
		m.histIdx = len(h)
		m.draft = append([]rune{}, m.input...)
	}
	next := m.histIdx + dir
	if next < 0 || next > len(h) {
		return
	}
	m.histIdx = next
	if next == len(h) {
		m.input = append([]rune{}, m.draft...)
	} else {
		m.input = []rune(h[next])
	}
	m.cursor = len(m.input)
}

func (m *Model) complete() tea.Cmd {
	before := string(m.input[:m.cursor])
	word, cands := m.sh.Complete(before)
	if len(cands) == 0 {
		return nil
	}
	if len(cands) == 1 {
		c := cands[0]
		if !strings.HasSuffix(c, "/") {
			c += " "
		}
		m.replaceWord(word, c)
		return nil
	}
	if p := commonPrefix(cands); len(p) > len(word) {
		m.replaceWord(word, p)
		return nil
	}
	if !m.lastTab {
		return nil
	}
	// Second Tab: list the candidates, as bash does.
	names := make([]string, len(cands))
	for i, c := range cands {
		c = strings.TrimSuffix(c, "/")
		if i := strings.LastIndexByte(c, '/'); i >= 0 {
			c = c[i+1:]
		}
		if strings.HasSuffix(cands[i], "/") {
			c += "/"
		}
		names[i] = c
	}
	return tea.Println(m.req.prompt + string(m.input) + "\n" + layout(names, m.width))
}

func (m *Model) replaceWord(word, with string) {
	start := m.cursor - len([]rune(word))
	in := append([]rune{}, m.input[:start]...)
	in = append(in, []rune(with)...)
	in = append(in, m.input[m.cursor:]...)
	m.input = in
	m.cursor = start + len([]rune(with))
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

func wordLeft(in []rune, i int) int {
	for i > 0 && unicode.IsSpace(in[i-1]) {
		i--
	}
	for i > 0 && !unicode.IsSpace(in[i-1]) {
		i--
	}
	return i
}

func wordRight(in []rune, i int) int {
	for i < len(in) && unicode.IsSpace(in[i]) {
		i++
	}
	for i < len(in) && !unicode.IsSpace(in[i]) {
		i++
	}
	return i
}

// View implements tea.Model. It shows the unfinished output line (or the
// prompt) followed by the input, wrapped to the terminal width, with the
// cursor placed where the next character will go.
func (m *Model) View() tea.View {
	if m.quitting {
		return tea.NewView("")
	}
	prefix := m.partial
	shown := string(m.input)
	before := string(m.input[:m.cursor])
	if m.req != nil {
		prefix = m.req.prompt
		if !m.req.echo {
			shown, before = "", ""
		}
	}
	w := m.width
	if w <= 0 {
		w = 80
	}
	content := prefix + shown
	pos := ansi.StringWidth(prefix) + ansi.StringWidth(before)
	wrapped := ansi.Hardwrap(content, w, true)
	lines := strings.Count(wrapped, "\n") + 1
	y, x := pos/w, pos%w
	for lines <= y {
		wrapped += "\n"
		lines++
	}
	v := tea.NewView(wrapped)
	v.Cursor = tea.NewCursor(x, y)
	return v
}

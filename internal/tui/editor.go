package tui

import (
	"strings"
	"unicode"
)

// Editor is the line being typed at the prompt: text, a cursor, and history
// browsing, with readline-style key bindings. It knows nothing about Bubble
// Tea, so it is easy to test.
type Editor struct {
	text   []rune
	cursor int // rune index into text

	// While browsing history, histIdx is the entry shown and draft is the
	// line that was being typed before. histIdx is -1 when not browsing.
	histIdx int
	draft   []rune
}

// NewEditor returns an empty editor.
func NewEditor() *Editor { return &Editor{histIdx: -1} }

// String returns the whole line.
func (ed *Editor) String() string { return string(ed.text) }

// BeforeCursor returns the text left of the cursor.
func (ed *Editor) BeforeCursor() string { return string(ed.text[:ed.cursor]) }

// Empty reports whether the line is empty.
func (ed *Editor) Empty() bool { return len(ed.text) == 0 }

// Set replaces the line and moves the cursor to the end.
func (ed *Editor) Set(s string) {
	ed.text = []rune(s)
	ed.cursor = len(ed.text)
}

// Reset clears the line and stops history browsing.
func (ed *Editor) Reset() {
	ed.text, ed.cursor = nil, 0
	ed.histIdx, ed.draft = -1, nil
}

// Insert types s at the cursor. Control characters are dropped.
func (ed *Editor) Insert(s string) {
	rs := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	ed.text = append(ed.text[:ed.cursor], append(rs, ed.text[ed.cursor:]...)...)
	ed.cursor += len(rs)
}

// ReplaceBeforeCursor replaces the word that ends at the cursor, as tab
// completion does.
func (ed *Editor) ReplaceBeforeCursor(word, with string) {
	start := ed.cursor - len([]rune(word))
	rest := append([]rune{}, ed.text[ed.cursor:]...)
	ed.text = append(append(ed.text[:start], []rune(with)...), rest...)
	ed.cursor = start + len([]rune(with))
}

// bindings maps keys to editing actions, as in bash's emacs mode.
var bindings = map[string]func(*Editor){
	"backspace":     (*Editor).backspace,
	"ctrl+h":        (*Editor).backspace,
	"delete":        (*Editor).deleteChar,
	"ctrl+d":        (*Editor).deleteChar,
	"left":          func(ed *Editor) { ed.cursor = max(0, ed.cursor-1) },
	"ctrl+b":        func(ed *Editor) { ed.cursor = max(0, ed.cursor-1) },
	"right":         func(ed *Editor) { ed.cursor = min(len(ed.text), ed.cursor+1) },
	"ctrl+f":        func(ed *Editor) { ed.cursor = min(len(ed.text), ed.cursor+1) },
	"home":          func(ed *Editor) { ed.cursor = 0 },
	"ctrl+a":        func(ed *Editor) { ed.cursor = 0 },
	"end":           func(ed *Editor) { ed.cursor = len(ed.text) },
	"ctrl+e":        func(ed *Editor) { ed.cursor = len(ed.text) },
	"alt+b":         func(ed *Editor) { ed.cursor = ed.wordLeft() },
	"ctrl+left":     func(ed *Editor) { ed.cursor = ed.wordLeft() },
	"alt+f":         func(ed *Editor) { ed.cursor = ed.wordRight() },
	"ctrl+right":    func(ed *Editor) { ed.cursor = ed.wordRight() },
	"ctrl+u":        (*Editor).killToStart,
	"ctrl+k":        func(ed *Editor) { ed.text = ed.text[:ed.cursor] },
	"ctrl+w":        (*Editor).killWord,
	"alt+backspace": (*Editor).killWord,
}

// Key applies an editing key such as "ctrl+w" and reports whether it was
// one.
func (ed *Editor) Key(key string) bool {
	f, ok := bindings[key]
	if ok {
		f(ed)
	}
	return ok
}

func (ed *Editor) backspace() {
	if ed.cursor > 0 {
		ed.text = append(ed.text[:ed.cursor-1], ed.text[ed.cursor:]...)
		ed.cursor--
	}
}

func (ed *Editor) deleteChar() {
	if ed.cursor < len(ed.text) {
		ed.text = append(ed.text[:ed.cursor], ed.text[ed.cursor+1:]...)
	}
}

func (ed *Editor) killToStart() {
	ed.text = append([]rune{}, ed.text[ed.cursor:]...)
	ed.cursor = 0
}

func (ed *Editor) killWord() {
	start := ed.wordLeft()
	ed.text = append(ed.text[:start], ed.text[ed.cursor:]...)
	ed.cursor = start
}

func (ed *Editor) wordLeft() int {
	i := ed.cursor
	for i > 0 && unicode.IsSpace(ed.text[i-1]) {
		i--
	}
	for i > 0 && !unicode.IsSpace(ed.text[i-1]) {
		i--
	}
	return i
}

func (ed *Editor) wordRight() int {
	i := ed.cursor
	for i < len(ed.text) && unicode.IsSpace(ed.text[i]) {
		i++
	}
	for i < len(ed.text) && !unicode.IsSpace(ed.text[i]) {
		i++
	}
	return i
}

// History moves through history: dir -1 is older (up), +1 is newer (down).
// Going past the newest entry brings back the line being typed.
func (ed *Editor) History(history []string, dir int) {
	if ed.histIdx < 0 {
		ed.histIdx = len(history)
		ed.draft = append([]rune{}, ed.text...)
	}
	next := ed.histIdx + dir
	if next < 0 || next > len(history) {
		return
	}
	ed.histIdx = next
	if next == len(history) {
		ed.Set(string(ed.draft))
	} else {
		ed.Set(history[next])
	}
}

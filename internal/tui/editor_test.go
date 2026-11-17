package tui

import "testing"

// show renders the line with | at the cursor.
func show(ed *Editor) string { return ed.BeforeCursor() + "|" + ed.String()[len(ed.BeforeCursor()):] }

func TestEditorKeys(t *testing.T) {
	tests := []struct {
		start string // | marks the cursor
		keys  []string
		want  string
	}{
		{"abc|", []string{"backspace"}, "ab|"},
		{"|abc", []string{"backspace"}, "|abc"},
		{"a|bc", []string{"delete"}, "a|c"},
		{"abc|", []string{"delete"}, "abc|"},
		{"abc|", []string{"left", "left"}, "a|bc"},
		{"|abc", []string{"left"}, "|abc"},
		{"abc|", []string{"home", "right"}, "a|bc"},
		{"a|bc", []string{"end"}, "abc|"},
		{"ls -la /tmp|", []string{"ctrl+a", "ctrl+f", "ctrl+e", "ctrl+b"}, "ls -la /tm|p"},
		{"echo hello world|", []string{"alt+b"}, "echo hello |world"},
		{"echo hello world|", []string{"alt+b", "alt+b", "alt+f"}, "echo hello| world"},
		{"echo hello world|", []string{"ctrl+w"}, "echo hello |"},
		{"echo hello   |", []string{"ctrl+w"}, "echo |"},
		{"echo hello wor|ld", []string{"ctrl+u"}, "|ld"},
		{"echo hel|lo", []string{"ctrl+k"}, "echo hel|"},
		{"héllo wörld|", []string{"left", "backspace"}, "héllo wör|d"},
	}
	for _, tt := range tests {
		ed := NewEditor()
		before, after, _ := cut(tt.start)
		ed.Set(before + after)
		ed.cursor = len([]rune(before))
		for _, k := range tt.keys {
			if !ed.Key(k) {
				t.Fatalf("%q is not an editing key", k)
			}
		}
		if got := show(ed); got != tt.want {
			t.Errorf("%q + %v = %q, want %q", tt.start, tt.keys, got, tt.want)
		}
	}
}

func cut(s string) (string, string, bool) {
	for i := range s {
		if s[i] == '|' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func TestEditorInsert(t *testing.T) {
	ed := NewEditor()
	ed.Insert("echo ")
	ed.Insert("hi\x07\t!") // control characters are dropped
	ed.Key("home")
	ed.Insert("$ ")
	if got := show(ed); got != "$ |echo hi!" {
		t.Errorf("got %q", got)
	}
	if ed.Key("enter") {
		t.Error("enter is not an editing key")
	}
}

func TestEditorHistory(t *testing.T) {
	history := []string{"one", "two"}
	ed := NewEditor()
	ed.Insert("draft")

	steps := []struct {
		dir  int
		want string
	}{
		{-1, "two|"}, {-1, "one|"}, {-1, "one|"}, // stops at the oldest
		{+1, "two|"}, {+1, "draft|"}, {+1, "draft|"}, // back to the draft
	}
	for i, s := range steps {
		ed.History(history, s.dir)
		if got := show(ed); got != s.want {
			t.Errorf("step %d: got %q, want %q", i, got, s.want)
		}
	}
	ed.Reset()
	ed.History(history, -1)
	if ed.String() != "two" {
		t.Errorf("after reset: %q", ed.String())
	}
}

func TestEditorReplaceBeforeCursor(t *testing.T) {
	ed := NewEditor()
	ed.Set("cat /etc/ho tail")
	ed.cursor = len("cat /etc/ho")
	ed.ReplaceBeforeCursor("/etc/ho", "/etc/hostname ")
	if got := show(ed); got != "cat /etc/hostname | tail" {
		t.Errorf("got %q", got)
	}
}

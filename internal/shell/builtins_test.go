package shell

import (
	"testing"
)

func TestUnescape(t *testing.T) {
	tests := []struct{ in, want string }{
		{`a\tb\nc`, "a\tb\nc"},
		{`\x41\x4a`, "AJ"},
		{`\101\0102`, "AB"},
		{`\177ELF`, "\x7fELF"},
		{`back\\slash`, `back\slash`},
		{`\q`, `\q`},
		{`stop\cignored`, "stop"},
	}
	for _, tt := range tests {
		if got, _ := Unescape(tt.in); got != tt.want {
			t.Errorf("Unescape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSprintf(t *testing.T) {
	tests := []struct {
		format string
		args   []string
		want   string
	}{
		{"%s-%d\n", []string{"a", "7"}, "a-7\n"},
		{"%5s|%-3s|", []string{"ab", "c"}, "   ab|c  |"},
		{"%x %o %c", []string{"255", "8", "hello"}, "ff 10 h"},
		{"%b", []string{`x\ty`}, "x\ty"},
		{"100%%", nil, "100%"},
		{`\177ELF%s\n`, []string{"!"}, "\x7fELF!\n"},
		{"%d", []string{"oops"}, "0"},
	}
	for _, tt := range tests {
		if got, _ := Sprintf(tt.format, tt.args); got != tt.want {
			t.Errorf("Sprintf(%q, %q) = %q, want %q", tt.format, tt.args, got, tt.want)
		}
	}
}

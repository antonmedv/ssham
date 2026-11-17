package shell

import "testing"

func TestArith(t *testing.T) {
	vars := map[string]string{"x": "5", "y": " 2 ", "s": "abc"}
	tests := []struct {
		expr string
		want int64
	}{
		{"1", 1},
		{"2 + 3 * 4", 14},
		{"(2 + 3) * 4", 20},
		{"10 / 3", 3},
		{"10 % 3", 1},
		{"-x + 1", -4},
		{"x * y", 10},
		{"x > y && y > 0", 1},
		{"x == 4 || !0", 1},
		{"x <= 4", 0},
		{"undefined + 1", 1},
		{"s + 1", 1},
		{"0x10 + 010", 24},
	}
	for _, tt := range tests {
		got, err := arith(tt.expr, func(n string) string { return vars[n] })
		if err != nil || got != tt.want {
			t.Errorf("arith(%q) = %d, %v; want %d", tt.expr, got, err, tt.want)
		}
	}
	for expr, want := range map[string]error{
		"1 / 0": errDivideZero, "1 % 0": errDivideZero,
		"2 +": errArithSyntax, "(1": errArithSyntax, "1 2": errArithSyntax, "": errArithSyntax, "1 @ 2": errArithSyntax,
	} {
		if _, err := arith(expr, func(string) string { return "" }); err != want {
			t.Errorf("arith(%q) error = %v, want %v", expr, err, want)
		}
	}
}

func TestTrimPattern(t *testing.T) {
	v := "/tmp/dir/file.tar.gz"
	for _, tt := range []struct {
		pattern         string
		prefix, longest bool
		want            string
	}{
		{"*/", true, false, "tmp/dir/file.tar.gz"},
		{"*/", true, true, "file.tar.gz"},
		{".*", false, false, "/tmp/dir/file.tar"},
		{".*", false, true, "/tmp/dir/file"},
		{"/t?p", true, false, "/dir/file.tar.gz"},
		{"[a-z]z", false, false, "/tmp/dir/file.tar."},
		{"nomatch", true, true, v},
	} {
		if got := trimPattern(v, tt.pattern, tt.prefix, tt.longest); got != tt.want {
			t.Errorf("trim(%q, prefix=%v, longest=%v) = %q, want %q", tt.pattern, tt.prefix, tt.longest, got, tt.want)
		}
	}
}

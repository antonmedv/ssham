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
		{"1 / 0", 0},
		{"2 +", 0},
		{"(1", 0},
		{"1 2", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := arith(tt.expr, func(n string) string { return vars[n] }); got != tt.want {
			t.Errorf("arith(%q) = %d, want %d", tt.expr, got, tt.want)
		}
	}
}

package crypt

import "testing"

func TestMD5(t *testing.T) {
	// Vectors from `openssl passwd -1 -salt SALT PASSWORD`.
	tests := []struct{ pw, salt, want string }{
		{"xc3511", "Sw0mXkPq", "$1$Sw0mXkPq$KeHmekVeDw1lND1V1CK9C."},
		{"", "abc", "$1$abc$Or2rbeUYTvt12aiVzMuS/."},
		{"a-very-long-password-over-sixteen-bytes", "12345678", "$1$12345678$6ej7GvKWvXVTitQjVA4MN1"},
	}
	for _, tt := range tests {
		if got := MD5(tt.pw, tt.salt); got != tt.want {
			t.Errorf("MD5(%q, %q) = %s, want %s", tt.pw, tt.salt, got, tt.want)
		}
	}
}

package shell

import "testing"

func TestLinkTarget(t *testing.T) {
	for dir, want := range map[string]string{
		"/bin":      "busybox",
		"/sbin":     "../bin/busybox",
		"/usr/bin":  "../../bin/busybox",
		"/usr/sbin": "../../bin/busybox",
	} {
		if got := linkTarget(dir); got != want {
			t.Errorf("linkTarget(%s) = %s, want %s", dir, got, want)
		}
	}
}

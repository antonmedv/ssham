package shell_test

import (
	"testing"
	"time"

	"github.com/antonmedv/ssham/internal/shelltest"
)

func TestForkBombIsBounded(t *testing.T) {
	for _, line := range []string{
		"f(){ f|f& }; f",
		"f(){ f; f; }; f",
		"bomb() { bomb | bomb & }; bomb",
	} {
		s := shelltest.New(t, "root")
		start := time.Now()
		s.Run(line)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%q took %v", line, d)
		}
	}
}

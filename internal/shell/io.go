package shell

import (
	"bytes"
	"errors"
	"io"

	"github.com/antonmedv/ssham/internal/audit"
)

// ttyReader lets commands like a bare `cat` read lines from the terminal.
type ttyReader struct {
	s   *Shell
	buf []byte
	eof bool
}

func (r *ttyReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		if r.eof {
			return 0, io.EOF
		}
		line, err := r.s.term.ReadLine("", true)
		if err != nil {
			r.eof = true
			if errors.Is(err, ErrInterrupt) {
				r.s.Interrupt()
			}
			return 0, io.EOF
		}
		r.s.log.Event(audit.Stdin, "line", line)
		r.buf = []byte(line + "\n")
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// limitedBuffer is a bytes.Buffer that silently drops data past max.
type limitedBuffer struct {
	bytes.Buffer
	max int
	// endless is set when the output would never have ended, like that
	// of cat /dev/urandom: only the first part is here.
	endless bool
}

// endlessReader is the read end of a pipe whose writer never ends.
type endlessReader struct{ *bytes.Reader }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room < len(p) {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func isText(b []byte) bool {
	if len(b) > 512 {
		b = b[:512]
	}
	return !bytes.ContainsRune(b, 0)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// Commands that stop reading once they have what they need, and filters
// that pass an endless stream on, as far as the pipe takes it.
var (
	prefixReaders = map[string]bool{"head": true, "dd": true, "read": true}
	streamFilters = map[string]bool{"cat": true, "tr": true, "sed": true, "grep": true, "egrep": true, "fgrep": true, "cut": true, "awk": true, "tee": true, "uniq": true}
)

// Package audit records everything an attacker does in the honeypot as
// structured JSON events.
package audit

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Logger writes honeypot events as JSON lines. It is safe for concurrent use.
type Logger struct {
	log    *slog.Logger
	closer io.Closer
}

// New returns a Logger that writes JSON events to w.
func New(w io.Writer) *Logger {
	return &Logger{log: slog.New(slog.NewJSONHandler(&syncWriter{w: w}, nil))}
}

// Open returns a Logger that appends JSON events to the file at path,
// creating it (and its directory) if needed. The path "-" means stdout.
func Open(path string) (*Logger, error) {
	if path == "-" || path == "" {
		return New(os.Stdout), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	l := New(f)
	l.closer = f
	return l, nil
}

// Close closes the underlying file, if any.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// Event records a single event with the given attributes.
func (l *Logger) Event(event string, attrs ...any) {
	l.log.Info(event, attrs...)
}

// Session returns a logger scoped to one SSH session; every event it records
// carries the session ID and remote address.
func (l *Logger) Session(id, remote string) *SessionLogger {
	return &SessionLogger{log: l.log.With("session", id, "remote", remote)}
}

// SessionLogger records events for one SSH session.
type SessionLogger struct {
	log *slog.Logger
}

// Event records a single event with the given attributes.
func (s *SessionLogger) Event(event string, attrs ...any) {
	if s == nil {
		return
	}
	s.log.Info(event, attrs...)
}

// syncWriter serializes writes so concurrent sessions never interleave
// partial JSON lines.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

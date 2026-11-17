// Command ssham is an SSH honeypot. It accepts common default passwords, presents
// the BusyBox shell of an IP camera, built with Wish, and
// records every credential, command, and download attempt as JSON lines. No command is
// ever executed on the host and no outbound connection is ever made.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"charm.land/ssh"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/server"
)

func main() {
	var (
		addr        = flag.String("addr", ":2222", "address to listen on")
		hostKeyDir  = flag.String("host-key-dir", ".ssh", "directory with the SSH host keys (generated if missing)")
		hostname    = flag.String("hostname", "ipcam", "hostname of the device")
		kernel      = flag.String("kernel", "4.9.37", "kernel release shown by uname")
		version     = flag.String("version", "dropbear_2019.78", "SSH server version banner (without SSH-2.0-)")
		logPath     = flag.String("log", "-", "file to append JSON audit events to (- for stdout)")
		statePath   = flag.String("state", "", "file to keep the camera's files and uptime in across restarts (none if empty)")
		maxSessions = flag.Int("max-sessions", 64, "maximum concurrent sessions")
		idle        = flag.Duration("idle-timeout", 30*time.Minute, "disconnect sessions idle for this long")
		maxTime     = flag.Duration("max-timeout", time.Hour, "disconnect sessions after this long regardless of activity")
		debug       = flag.Bool("debug", false, "verbose operational logging")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	auditLog, err := audit.Open(*logPath)
	if err != nil {
		logger.Error("open audit log", "err", err)
		os.Exit(1)
	}
	defer auditLog.Close()

	srv, err := server.New(server.Config{
		Addr:        *addr,
		HostKeyDir:  *hostKeyDir,
		Hostname:    *hostname,
		Kernel:      *kernel,
		Version:     *version,
		MaxSessions: *maxSessions,
		StatePath:   *statePath,
		IdleTimeout: *idle,
		MaxTimeout:  *maxTime,
		Audit:       auditLog,
		Log:         logger,
	})
	if err != nil {
		logger.Error("create server", "err", err)
		os.Exit(1)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	logger.Info("ssham listening", "addr", *addr, "audit_log", *logPath)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			logger.Error("serve", "err", err)
			done <- syscall.SIGTERM
		}
	}()

	<-done
	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		logger.Error("shutdown", "err", err)
	}
}

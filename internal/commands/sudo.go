package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "sudo", Run: cmdSudo},
		shell.Command{Name: "su", Run: cmdSu},
	)
}

const sudoUsage = `usage: sudo -h | -K | -k | -V
usage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo [-ABbEHkNnPS] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i | -s] [command [arg ...]]
`

// cmdSudo accepts any non-empty password (and logs it), then runs the
// command as root. sudo -i, sudo -s, sudo su and sudo bash open a root
// shell that lasts until exit.
func cmdSudo(e *shell.Env) int {
	args := e.Args[1:]
	login, shellMode, list := false, false, false
	target := "root"
options:
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		a := args[0]
		args = args[1:]
		switch a {
		case "--":
			break options
		case "-i", "--login":
			login = true
		case "-s", "--shell":
			shellMode = true
		case "-l", "--list":
			list = true
		case "-u", "--user":
			if len(args) > 0 {
				target, args = args[0], args[1:]
			}
		}
	}
	if !list && !login && !shellMode && len(args) == 0 {
		fmt.Fprint(e.Stderr, sudoUsage)
		return 1
	}
	if !sudoAuthenticate(e) {
		return 1
	}
	if list {
		u, h := e.User().Name, e.Host().Hostname
		e.Printf("Matching Defaults entries for %s on %s:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin, use_pty\n\nUser %s may run the following commands on %s:\n    (ALL : ALL) ALL\n", u, h, u, h)
		return 0
	}
	user, ok := e.LookupUser(target)
	if !ok {
		fmt.Fprintf(e.Stderr, "sudo: unknown user %s\nsudo: error initializing audit plugin sudoers_audit\n", target)
		return 1
	}

	// Commands that open a shell: sudo -i, sudo -s, sudo bash, sudo su [-].
	opensShell := len(args) == 0 ||
		(len(args) == 1 && isShellName(args[0])) ||
		args[0] == "su"
	if opensShell {
		cwd := ""
		if login || (len(args) > 1 && args[0] == "su" && (args[1] == "-" || args[1] == "-l")) {
			cwd = user.Home
		}
		e.Login(user, cwd)
		return 0
	}
	return e.RunAs(user, func(e *shell.Env) int { return e.Run(args...) })
}

// sudoAuthenticate asks for a password once per session, like sudo's
// credential cache. Any non-empty password is accepted.
func sudoAuthenticate(e *shell.Env) bool {
	if e.User().IsRoot() || e.SudoCached() {
		return true
	}
	for range 3 {
		pw, err := e.ReadLine(fmt.Sprintf("[sudo] password for %s: ", e.User().Name), false)
		if err != nil {
			return false
		}
		e.Log(audit.PasswordEntered, "context", "sudo", "user", e.User().Name, "password", pw)
		if pw != "" {
			e.CacheSudo()
			return true
		}
		fmt.Fprintln(e.Stderr, "Sorry, try again.")
	}
	fmt.Fprintln(e.Stderr, "sudo: 3 incorrect password attempts")
	return false
}

// cmdSu always fails for non-root users, after logging the password they
// tried. For root it switches user.
func cmdSu(e *shell.Env) int {
	args := e.Args[1:]
	target := "root"
	login := false
	var script string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-" || a == "-l" || a == "--login":
			login = true
		case a == "-c" || a == "--command":
			if i+1 < len(args) {
				script = args[i+1]
				i++
			}
		case !strings.HasPrefix(a, "-"):
			target = a
		}
	}
	user, ok := e.LookupUser(target)
	if !ok {
		fmt.Fprintf(e.Stderr, "su: user %s does not exist or the user entry does not contain all the required fields\n", target)
		return 1
	}
	if !e.User().IsRoot() {
		pw, err := e.ReadLine("Password: ", false)
		if err != nil {
			return 1
		}
		e.Log(audit.PasswordEntered, "context", "su", "user", target, "password", pw)
		if !e.Sleep(time.Duration(1500+e.Rand().IntN(1500)) * time.Millisecond) {
			return 1
		}
		fmt.Fprintln(e.Stderr, "su: Authentication failure")
		return 1
	}
	if script != "" {
		return e.RunAs(user, func(e *shell.Env) int { return e.RunScript(script) })
	}
	cwd := ""
	if login {
		cwd = user.Home
	}
	e.Login(user, cwd)
	return 0
}

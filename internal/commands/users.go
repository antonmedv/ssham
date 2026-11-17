package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "whoami", Dir: "/usr/bin", Usage: "", Run: cmdWhoami},
		shell.Command{Name: "id", Dir: "/usr/bin", Usage: "[OPTIONS] [USER]", Run: cmdId},
		shell.Command{Name: "passwd", Dir: "/usr/bin", Usage: "[OPTIONS] [USER]", Run: cmdPasswd},
		shell.Command{Name: "chpasswd", Dir: "/usr/sbin", Usage: "[--md5|--encrypted|--crypt-method|--root]", Run: cmdChpasswd},
	)
}

func cmdWhoami(e *shell.Env) int {
	e.Printf("%s\n", e.User().Name)
	return 0
}

func cmdId(e *shell.Env) int {
	o := e.Flags()
	u := e.User()
	if len(o.Args) > 0 {
		var ok bool
		if u, ok = e.LookupUser(o.Args[0]); !ok {
			e.Errorf("unknown user %s", o.Args[0])
			return 1
		}
	}
	switch {
	case o.Has("u") && o.Has("n"):
		e.Printf("%s\n", u.Name)
	case o.Has("u"):
		e.Printf("%d\n", u.UID)
	case o.Has("g"):
		e.Printf("%d\n", u.GID)
	case o.Has("G"):
		var ids []string
		for _, g := range u.Groups {
			ids = append(ids, strconv.Itoa(e.GroupID(g)))
		}
		e.Printf("%s\n", strings.Join(ids, " "))
	default:
		var groups []string
		for _, g := range u.Groups {
			groups = append(groups, fmt.Sprintf("%d(%s)", e.GroupID(g), g))
		}
		e.Printf("uid=%d(%s) gid=%d(%s) groups=%s\n", u.UID, u.Name, u.GID, u.Groups[0], strings.Join(groups, ","))
	}
	return 0
}

// setPassword replaces user's hash in /etc/shadow (a link to flash, so it
// is writable). The hash only looks like md5-crypt; it is never checked.
func setPassword(e *shell.Env, user string) error {
	data, err := e.FS.AsRoot().ReadFile("/etc/shadow")
	if err != nil {
		return err
	}
	const chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	random := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = chars[e.Rand().IntN(len(chars))]
		}
		return string(b)
	}
	days := strconv.FormatInt(e.Now().Unix()/86400, 10)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	for i, l := range lines {
		f := strings.Split(l, ":")
		if len(f) > 2 && f[0] == user {
			f[1], f[2] = "$1$"+random(8)+"$"+random(22), days
			lines[i] = strings.Join(f, ":")
		}
	}
	return e.FS.AsRoot().WriteFile("/etc/shadow", []byte(strings.Join(lines, "\n")+"\n"))
}

func cmdChpasswd(e *shell.Env) int {
	if !e.User().IsRoot() {
		e.Errorf("must be run by root")
		return 1
	}
	for _, l := range splitLines(e.ReadStdin()) {
		user, pw, ok := strings.Cut(l, ":")
		if !ok {
			e.Errorf("missing new password")
			return 1
		}
		e.Log(audit.PasswordChange, "method", "chpasswd", "user", user, "password", pw)
		if _, ok := e.LookupUser(user); !ok {
			e.Errorf("unknown user %s", user)
			return 1
		}
		if err := setPassword(e, user); err != nil {
			e.Errorf("can't open '/etc/shadow': %s", err)
			return 1
		}
	}
	return 0
}

func cmdPasswd(e *shell.Env) int {
	o := e.Flags()
	target := e.User().Name
	if len(o.Args) > 0 {
		target = o.Args[0]
	}
	if _, ok := e.LookupUser(target); !ok {
		e.Errorf("unknown user %s", target)
		return 1
	}
	e.Printf("Changing password for %s\n", target)
	pw1, err := e.ReadLine("New password: ", false)
	if err != nil {
		return 1
	}
	pw2, err := e.ReadLine("Retype password: ", false)
	if err != nil {
		return 1
	}
	e.Log(audit.PasswordChange, "method", "passwd", "user", target, "password", pw1, "retyped", pw2)
	if pw1 != pw2 {
		e.Print("Passwords don't match\n")
		e.Errorf("password for %s is unchanged", target)
		return 1
	}
	if err := setPassword(e, target); err != nil {
		e.Errorf("can't open '/etc/shadow': %s", err)
		return 1
	}
	e.Errorf("password for %s changed by %s", target, e.User().Name)
	return 0
}

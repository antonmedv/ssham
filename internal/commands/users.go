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
		shell.Command{Name: "whoami", Run: cmdWhoami},
		shell.Command{Name: "id", Run: cmdId},
		shell.Command{Name: "groups", Run: cmdGroups},
		shell.Command{Name: "useradd", Aliases: []string{"adduser", "usermod"}, Dir: "/usr/sbin", Run: cmdUseradd},
		shell.Command{Name: "chpasswd", Dir: "/usr/sbin", Run: cmdChpasswd},
		shell.Command{Name: "passwd", Run: cmdPasswd},
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
			e.Errorf("'%s': no such user", o.Args[0])
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

func cmdGroups(e *shell.Env) int {
	u := e.User()
	if len(e.Args) > 1 {
		var ok bool
		if u, ok = e.LookupUser(e.Args[1]); !ok {
			e.Errorf("'%s': no such user", e.Args[1])
			return 1
		}
		e.Printf("%s : ", u.Name)
	}
	e.Printf("%s\n", strings.Join(u.Groups, " "))
	return 0
}

func cmdUseradd(e *shell.Env) int {
	o := e.Flags("p", "d", "s", "g", "G", "c", "u", "password", "home", "shell")
	if !e.User().IsRoot() {
		fmt.Fprintf(e.Stderr, "%s: Permission denied.\n%s: cannot lock /etc/passwd; try again later.\n", e.Args[0], e.Args[0])
		return 1
	}
	if len(o.Args) == 0 {
		fmt.Fprintf(e.Stderr, "Usage: %s [options] LOGIN\n", e.Args[0])
		return 2
	}
	user := o.Args[len(o.Args)-1]
	if e.Args[0] == "usermod" {
		e.Log(audit.UserModify, "user", user, "args", strings.Join(e.Args[1:], " "))
		return 0
	}
	if _, exists := e.LookupUser(user); exists {
		fmt.Fprintf(e.Stderr, "%s: user '%s' already exists\n", e.Args[0], user)
		return 9
	}
	pw, _ := o.Value("p", "password")
	e.Log(audit.UserAdd, "user", user, "password_hash", pw, "args", strings.Join(e.Args[1:], " "))
	uid := nextUID(e)
	_ = e.FS.AsRoot().AppendFile("/etc/passwd", []byte(fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/sh\n", user, uid, uid, user)))
	_ = e.FS.AsRoot().AppendFile("/etc/group", []byte(fmt.Sprintf("%s:x:%d:\n", user, uid)))
	_ = e.FS.AsRoot().AppendFile("/etc/shadow", []byte(fmt.Sprintf("%s:%s:20044:0:99999:7:::\n", user, map[bool]string{true: "!", false: pw}[pw == ""])))
	if e.Args[0] == "adduser" || o.Has("m", "create-home") {
		_ = e.FS.AsRoot().Mkdir("/home/"+user, true)
		_ = e.FS.AsRoot().Chmod("/home/"+user, 0o750)
		_ = e.FS.AsRoot().Chown("/home/"+user, user, user)
	}
	if e.Args[0] == "adduser" {
		e.Printf("info: Adding user `%s' ...\ninfo: Selecting UID/GID from range 1000 to 59999 ...\ninfo: Adding new group `%s' (%d) ...\ninfo: Adding new user `%s' (%d) with group `%s (%d)' ...\ninfo: Creating home directory `/home/%s' ...\ninfo: Copying files from `/etc/skel' ...\n", user, user, uid, user, uid, user, uid, user)
		for i := 0; i < 2; i++ {
			label := "New password: "
			if i == 1 {
				label = "Retype new password: "
			}
			pw, err := e.ReadLine(label, false)
			if err != nil {
				return 1
			}
			e.Log(audit.PasswordEntered, "context", "adduser", "user", user, "password", pw)
		}
		e.Print("passwd: password updated successfully\n")
	}
	return 0
}

func cmdChpasswd(e *shell.Env) int {
	data := e.ReadStdin()
	for _, l := range splitLines(data) {
		user, pw, ok := strings.Cut(l, ":")
		if !ok {
			fmt.Fprintf(e.Stderr, "chpasswd: line 1: missing new password\n")
			return 1
		}
		e.Log(audit.PasswordChange, "method", "chpasswd", "user", user, "password", pw)
		if !e.User().IsRoot() {
			fmt.Fprintf(e.Stderr, "chpasswd: (user %s) pam_chauthtok() failed, error:\nAuthentication token manipulation error\nchpasswd: (line 1, user %s) password not changed\n", user, user)
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
		if !e.User().IsRoot() && target != e.User().Name {
			fmt.Fprintf(e.Stderr, "passwd: You may not view or modify password information for %s.\n", target)
			return 1
		}
	}
	if o.Has("stdin") {
		pw := strings.TrimSpace(e.ReadStdin())
		e.Log(audit.PasswordChange, "method", "passwd --stdin", "user", target, "password", pw)
		e.Print("passwd: unrecognized option '--stdin'\n")
		return 1
	}
	e.Printf("Changing password for %s.\n", target)
	prompts := []string{"Current password: ", "New password: ", "Retype new password: "}
	if e.User().IsRoot() {
		prompts = prompts[1:]
	}
	var pws []string
	for _, p := range prompts {
		pw, err := e.ReadLine(p, false)
		if err != nil {
			fmt.Fprintln(e.Stderr, "passwd: Authentication token manipulation error\npasswd: password unchanged")
			return 10
		}
		pws = append(pws, pw)
	}
	e.Log(audit.PasswordChange, "method", "passwd", "user", target, "passwords", strings.Join(pws, "\x00"))
	if pws[len(pws)-1] != pws[len(pws)-2] {
		fmt.Fprintln(e.Stderr, "Sorry, passwords do not match.\npasswd: Authentication token manipulation error\npasswd: password unchanged")
		return 10
	}
	e.Print("passwd: password updated successfully\n")
	return 0
}

// nextUID returns the first free uid from 1000 up, as useradd picks it.
func nextUID(e *shell.Env) int {
	data, _ := e.FS.AsRoot().ReadFile("/etc/passwd")
	uid := 1000
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) > 2 {
			if n, err := strconv.Atoi(f[2]); err == nil && n >= uid && n < 60000 {
				uid = n + 1
			}
		}
	}
	return uid
}

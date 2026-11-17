package shell

import (
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/vfs"
)

// User is an account from the fake /etc/passwd.
type User struct {
	Name   string
	UID    int
	GID    int
	Home   string
	Shell  string
	Groups []string // primary group first
}

// IsRoot reports whether u is the superuser.
func (u User) IsRoot() bool { return u.UID == 0 }

// lookupUser reads the account from the session's /etc/passwd and
// /etc/group, so `useradd` and friends are reflected everywhere.
func lookupUser(f *vfs.FS, name string) (User, bool) {
	passwd, _ := f.ReadFile("root", "/etc/passwd")
	for _, line := range strings.Split(string(passwd), "\n") {
		p := strings.Split(line, ":")
		if len(p) < 7 || p[0] != name {
			continue
		}
		u := User{Name: name, Home: p[5], Shell: p[6]}
		u.UID, _ = strconv.Atoi(p[2])
		u.GID, _ = strconv.Atoi(p[3])
		u.Groups = groupsOf(f, name, u.GID)
		return u, true
	}
	return User{}, false
}

func groupsOf(f *vfs.FS, user string, gid int) []string {
	data, _ := f.ReadFile("root", "/etc/group")
	var primary string
	var others []string
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Split(line, ":")
		if len(p) < 4 {
			continue
		}
		if id, _ := strconv.Atoi(p[2]); id == gid {
			primary = p[0]
			continue
		}
		for _, m := range strings.Split(p[3], ",") {
			if m == user {
				others = append(others, p[0])
			}
		}
	}
	if primary == "" {
		primary = user
	}
	return append([]string{primary}, others...)
}

// GroupID returns the numeric id of a group in /etc/group, or -1.
func groupID(f *vfs.FS, group string) int {
	data, _ := f.ReadFile("root", "/etc/group")
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Split(line, ":")
		if len(p) >= 3 && p[0] == group {
			id, _ := strconv.Atoi(p[2])
			return id
		}
	}
	return -1
}

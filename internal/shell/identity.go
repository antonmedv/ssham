package shell

import "fmt"

// identity is a saved user and working directory, restored when a nested
// shell (su, sudo -i, bash) exits.
type identity struct {
	user User
	cwd  string
}

// login switches to user as if a new shell had started, e.g. after su.
// If cwd is empty the working directory is kept.
func (s *Shell) login(user User, cwd string) {
	s.stack = append(s.stack, identity{s.user, s.cwd})
	s.setIdentity(identity{user, cwd})
}

// popIdentity returns to the previous shell. It reports false if this is
// the login shell.
func (s *Shell) popIdentity() bool {
	if len(s.stack) == 0 {
		return false
	}
	id := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	s.setIdentity(id)
	return true
}

func (s *Shell) setIdentity(id identity) {
	s.user = id.user
	if id.cwd != "" {
		s.cwd = id.cwd
	}
	s.vars["USER"], s.vars["LOGNAME"], s.vars["HOME"], s.vars["PWD"] = s.user.Name, s.user.Name, s.user.Home, s.cwd
	s.vars["SHLVL"] = fmt.Sprint(len(s.stack) + 1)
}

// runAs runs fn as user, then restores the current user and directory.
func (s *Shell) runAs(user User, fn func() int) int {
	saved := identity{s.user, s.cwd}
	s.user = user
	defer func() { s.user, s.cwd = saved.user, saved.cwd }()
	return fn()
}

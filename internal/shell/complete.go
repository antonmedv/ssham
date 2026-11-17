package shell

import (
	"path"
	"sort"
	"strings"
)

// Complete returns the possible completions of the word at the end of
// line. Each candidate is a full replacement for that word; directories end
// in "/". It must only be called while the shell is waiting for input.
func (s *Shell) Complete(line string) (word string, candidates []string) {
	start := strings.LastIndexAny(line, " \t") + 1
	word = line[start:]
	before := strings.TrimRight(line[:start], " \t")
	isCommand := before == "" || strings.HasSuffix(before, "|") || strings.HasSuffix(before, ";") ||
		strings.HasSuffix(before, "&") || strings.HasSuffix(before, "sudo")

	seen := map[string]bool{}
	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			candidates = append(candidates, c)
		}
	}

	if isCommand && !strings.Contains(word, "/") {
		for name := range builtins {
			if strings.HasPrefix(name, word) {
				add(name)
			}
		}
		for name := range s.aliases {
			if strings.HasPrefix(name, word) {
				add(name)
			}
		}
		for _, dir := range strings.Split(s.getVar("PATH"), ":") {
			ents, err := s.fs.ReadDir(s.user, dir)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if strings.HasPrefix(e.Name, word) && !e.IsDir() {
					add(e.Name)
				}
			}
		}
		sort.Strings(candidates)
		return word, candidates
	}

	dirPart, base := path.Split(word)
	lookup := dirPart
	switch {
	case strings.HasPrefix(dirPart, "~/"):
		lookup = s.home + dirPart[1:]
	case dirPart == "":
		lookup = "."
	}
	ents, err := s.fs.ReadDir(s.user, s.resolve(lookup))
	if err != nil {
		return word, nil
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name, base) || (strings.HasPrefix(e.Name, ".") && !strings.HasPrefix(base, ".")) {
			continue
		}
		c := dirPart + e.Name
		if n, err := s.fs.Stat(s.user, s.resolve(path.Join(lookup, e.Name))); err == nil && n.IsDir() {
			c += "/"
		}
		add(c)
	}
	return word, candidates
}

// Motd returns the login banner Ubuntu shows on an interactive login.
func (s *Shell) Motd() string {
	h := s.cfg.Host
	last := s.cfg.Started.Add(-26*3600*1e9 - 17*60*1e9)
	return "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux " + h.Kernel + " x86_64)\n\n" +
		" * Documentation:  https://help.ubuntu.com\n" +
		" * Management:     https://landscape.canonical.com\n" +
		" * Support:        https://ubuntu.com/pro\n\n" +
		" System information as of " + s.cfg.Started.UTC().Format("Mon Jan _2 15:04:05 UTC 2006") + "\n\n" +
		"  System load:  0.08              Processes:             112\n" +
		"  Usage of /:   6.3% of 77.35GB   Users logged in:       0\n" +
		"  Memory usage: 24%               IPv4 address for ens5: 10.0.2.15\n" +
		"  Swap usage:   0%\n\n" +
		"Expanded Security Maintenance for Applications is not enabled.\n\n" +
		"3 updates can be applied immediately.\n" +
		"To see these additional updates run: apt list --upgradable\n\n" +
		"Enable ESM Apps to receive additional future security updates.\n" +
		"See https://ubuntu.com/esm or run: sudo pro status\n\n\n" +
		"Last login: " + last.Format("Mon Jan _2 15:04:05 2006") + " from 10.0.2.2\n"
}

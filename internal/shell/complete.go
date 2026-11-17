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
			ents, err := s.fs.ReadDir(s.user.Name, dir)
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
		lookup = s.user.Home + dirPart[1:]
	case dirPart == "":
		lookup = "."
	}
	ents, err := s.fs.ReadDir(s.user.Name, s.resolve(lookup))
	if err != nil {
		return word, nil
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name, base) || (strings.HasPrefix(e.Name, ".") && !strings.HasPrefix(base, ".")) {
			continue
		}
		c := dirPart + e.Name
		if n, err := s.fs.Stat(s.user.Name, s.resolve(path.Join(lookup, e.Name))); err == nil && n.IsDir() {
			c += "/"
		}
		add(c)
	}
	return word, candidates
}

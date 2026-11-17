package commands

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "find", Dir: "/usr/bin", Usage: "[-HL] [PATH]... [OPTIONS] [ACTIONS]", Run: cmdFind},
	)
}

func cmdFind(e *shell.Env) int {
	args := e.Args[1:]
	var roots []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") && args[0] != "(" && args[0] != "!" {
		roots = append(roots, args[0])
		args = args[1:]
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var namePat, typ, iname string
	maxDepth := -1
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "-name":
			namePat = next()
		case "-iname":
			iname = strings.ToLower(next())
		case "-type":
			typ = next()
		case "-maxdepth":
			maxDepth, _ = strconv.Atoi(next())
		case "-perm", "-user", "-group", "-size", "-mtime", "-newer", "-path", "-mindepth":
			next()
		case "-exec", "-execdir", "-ok":
			for i < len(args) && args[i] != ";" && args[i] != "+" {
				i++
			}
		}
	}
	status := 0
	var walk func(p, shown string, depth int)
	walk = func(p, shown string, depth int) {
		if e.Ctx.Err() != nil {
			return
		}
		n, err := e.FS.Lstat(p)
		if err != nil {
			fmt.Fprintf(e.Stderr, "find: %s: %s\n", shown, err)
			status = 1
			return
		}
		match := true
		name := path.Base(p)
		if namePat != "" {
			match, _ = path.Match(namePat, name)
		}
		if match && iname != "" {
			match, _ = path.Match(iname, strings.ToLower(name))
		}
		if match && typ != "" {
			switch typ {
			case "f":
				match = !n.IsDir() && !n.IsLink()
			case "d":
				match = n.IsDir()
			case "l":
				match = n.IsLink()
			}
		}
		if match {
			e.Printf("%s\n", shown)
		}
		if !n.IsDir() || (maxDepth >= 0 && depth >= maxDepth) {
			return
		}
		children, err := e.FS.ReadDir(p)
		if err != nil {
			fmt.Fprintf(e.Stderr, "find: %s: %s\n", shown, err)
			status = 1
			return
		}
		for _, c := range children {
			child := shown + "/" + c.Name
			if shown == "/" {
				child = "/" + c.Name
			}
			walk(path.Join(p, c.Name), child, depth+1)
		}
	}
	for _, r := range roots {
		walk(e.FS.Abs(r), strings.TrimSuffix(r, "/")+map[bool]string{true: "/", false: ""}[r == "/"], 0)
	}
	return status
}

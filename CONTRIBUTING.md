# Contributing

## How it fits together

```
internal/server     SSH server (Wish): logins, sessions
internal/tui        what the attacker sees: prompt and line editor (Bubble Tea)
internal/shell      the fake bash: parsing, pipes, redirects, variables, builtins
internal/commands   the fake programs: ls, cat, wget, sudo, ...
internal/rootfs     the fake disk, as real files in rootfs/files/
internal/vfs        in-memory filesystem with users and permissions
internal/audit      the JSON log
internal/shelltest  test helpers: in-memory sessions and transcripts
```

Nothing runs on the host. A command is a Go function that reads and writes
the in-memory filesystem.

## Add a command

Create a file in `internal/commands/`:

```go
package commands

import (
	"strings"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(shell.Command{Name: "cowsay", Run: cmdCowsay})
}

func cmdCowsay(e *shell.Env) int {
	o := e.Flags("f") // parse -f VALUE and boolean flags
	e.Printf(" < %s >\n", strings.Join(o.Args, " "))
	return 0 // exit status
}
```

That's all. `register` also installs `/usr/bin/cowsay`, so `which`, tab
completion and `ls /usr/bin` see it too.

`e` is everything a command needs:

| | |
|---|---|
| `e.Args`, `e.Flags()` | arguments |
| `e.Print`, `e.Printf`, `e.Errorf` | output (`Errorf` prints `cowsay: ...` to stderr) |
| `e.ReadStdin()`, `e.ReadFiles(names)`, `e.ReadLine(prompt, echo)` | input |
| `e.FS` | the filesystem as the current user, relative to the working directory |
| `e.User()`, `e.LookupUser(name)`, `e.Host()`, `e.Session()` | who and where |
| `e.Now()`, `e.Rand()`, `e.Sleep(d)` | time and randomness (never use `time.Now` or `math/rand`) |
| `e.Log(audit.X, ...)` | record something interesting |
| `e.Run(args...)`, `e.RunAs(user, fn)`, `e.RunScript(src)` | run other commands |

## Add a file to the fake disk

Drop it into `internal/rootfs/files/`. For example,
`internal/rootfs/files/opt/backup.sh` appears as `/opt/backup.sh`.

- Files are owned by root with mode 0644. To change that, add the path to
  `modes` in `internal/rootfs/rootfs.go`.
- Files ending in `.tmpl` are templates: `{{.Hostname}}` and `{{.Kernel}}`
  work.

## Test it

Tests are transcripts: text files that look like a terminal session.

```
// internal/commands/testdata/cowsay.txt
$ cowsay hello world
 < hello world >
$ cowsay | wc -c
6
```

- `$ ` lines are commands. The lines after them are the expected output.
- `< ` lines are what the user types at a prompt (passwords, `read`).
- `@user admin` starts a new session as `admin`. Each file starts as root.
- `[exit N]` is shown when the exit status is not 0.

You don't need to type the output yourself. Write only the `$` lines, then run

```sh
go test ./internal/commands -update
```

and check the output with `git diff`. Is it what real Linux prints?

Time and randomness are fixed in tests, so the output is always the same.

Every command is also run automatically with junk arguments
(`TestEveryCommandSurvivesJunk`), and the shell is fuzzed (`FuzzShell`).
A command must never panic.

## Before you push

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

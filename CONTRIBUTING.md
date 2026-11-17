# Contributing

## How it fits together

```
internal/server     SSH server (Wish): logins, sessions
internal/tui        what the attacker sees: prompt and line editor (Bubble Tea)
internal/shell      the fake BusyBox ash: parsing, pipes, redirects, if/for/while, builtins
internal/commands   the BusyBox applets: ls, cat, wget, ps, ...
internal/rootfs     the camera's disk, as real files in rootfs/files/
internal/vfs        in-memory filesystem with users, permissions and read-only mounts
internal/audit      the JSON log
internal/shelltest  test helpers: in-memory sessions and transcripts
```

Nothing runs on the host. An applet is a Go function that reads and writes
the in-memory filesystem.

## The persona

ssham is a BusyBox-based IP camera. Keep it small and consistent:

- Only the applets in `internal/commands` exist. Anything else is
  `sh: NAME: not found` (exit 127), and `busybox NAME` is
  `NAME: applet not found`. Never add a command that silently does nothing.
- The shell is ash, not bash. Bash-only syntax (arrays, functions,
  `[[`, `${x/a/b}`, `<(...)`) fails with ash's syntax errors.
- `/` is a read-only squashfs. Only `/tmp`, `/var`, `/dev` and `/mnt/mtd`
  are writable, even for root.
- Messages follow BusyBox: `cat: can't open 'x': No such file or directory`.
- Every login is root. There is no sudo, su or useradd.

## Add an applet

Create a file in `internal/commands/`:

```go
package commands

import (
	"strings"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(shell.Command{Name: "cowsay", Dir: "/usr/bin", Usage: "[TEXT]...", Run: cmdCowsay})
}

func cmdCowsay(e *shell.Env) int {
	o := e.Flags("f") // parse -f VALUE and boolean flags
	if len(o.Args) == 0 {
		return e.Usage() // BusyBox's usage text, exit 1
	}
	e.Printf(" < %s >\n", strings.Join(o.Args, " "))
	return 0 // exit status
}
```

That's all. `register` links `/usr/bin/cowsay` to `/bin/busybox`, so
`busybox`, `which`, tab completion and `ls -l /usr/bin` all see it.

`e` is everything an applet needs:

| | |
|---|---|
| `e.Args`, `e.Flags()`, `e.Usage()` | arguments, and the usage text for misuse |
| `e.Print`, `e.Printf`, `e.Errorf` | output (`Errorf` prints `cowsay: ...` to stderr) |
| `e.ReadStdin()`, `e.ReadFiles(names)`, `e.ReadLine(prompt, echo)` | input |
| `e.FS` | the filesystem as the current user, relative to the working directory |
| `e.User()`, `e.LookupUser(name)`, `e.Host()`, `e.Session()` | who and where |
| `e.Now()`, `e.Rand()`, `e.Sleep(d)` | time and randomness (never use `time.Now` or `math/rand`) |
| `e.Log(audit.X, ...)` | record something interesting |
| `e.Run(args...)`, `e.RunApplet(args...)`, `e.RunScript(src)` | run other commands |

## Add a file to the camera's disk

Drop it into `internal/rootfs/files/`. For example,
`internal/rootfs/files/mnt/mtd/Config/ptz.conf` appears as
`/mnt/mtd/Config/ptz.conf`.

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
$ cowsay
BusyBox v1.31.1 (2021-03-12 11:24:03 CST) multi-call binary.

Usage: cowsay [TEXT]...
[exit 1]
```

- `$ ` lines are commands. The lines after them are the expected output.
- `< ` lines are what the user types at a prompt (passwords, `read`).
- `@user NAME` starts a new session.
- `[exit N]` is shown when the exit status is not 0.

You don't need to type the output yourself. Write only the `$` lines, then run

```sh
go test ./internal/commands -update
```

and check the output with `git diff`. Is it what a real BusyBox prints?

Time and randomness are fixed in tests, so the output is always the same.

Every applet is also run automatically with junk arguments
(`TestEveryCommandSurvivesJunk`), `busybox --list` is checked against what
works (`TestBusyboxListMatchesApplets`), and the shell is fuzzed
(`FuzzShell`). An applet must never panic.

## Known tells

Things a careful attacker could still notice. Fixes welcome.

- **Nothing persists across reconnects.** Each session starts from a fresh
  disk, so a file written to `/mnt/mtd` is gone at the next login.
- **The SSH handshake is Go's, not dropbear's.** The banner says
  `dropbear_2019.78`, but the offered key exchange and cipher lists come
  from `golang.org/x/crypto/ssh`, so SSH fingerprinting (e.g. HASSH)
  can tell.

## Before you push

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

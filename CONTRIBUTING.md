# Contributing

## How it fits together

```
internal/server     SSH server (Wish): logins, sessions
internal/tui        what the attacker sees: the pty, byte for byte like BusyBox's line editing
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
- The shell is BusyBox ash, which has functions, `case`, here-documents,
  `$RANDOM` and some bash extensions (`[[`, `${x:1:2}`, `${x/a/b}`).
  What ash lacks (arrays, `<(...)`, `function f {`) fails with ash's
  syntax errors.
- The camera's internet access is blocked: DNS and outside addresses time
  out (`internal/commands/net.go`). Only the camera itself and the router
  at 192.168.1.1 answer. Never fake a successful download.
- `/` is a read-only squashfs. Only `/tmp`, `/var`, `/dev` and `/mnt/mtd`
  are writable, even for root.
- Messages follow BusyBox: `cat: can't open 'x': No such file or directory`.
- All sessions share one camera: the same files, and the same process
  table (`ps` shows everyone). `reboot` really reboots it: everyone is cut
  off for a while, and only the flash (`/mnt/mtd`) keeps its files. With
  `-state`, files and uptime survive restarts of ssham.
- Only `root` and `admin` (also uid 0) can log in, with a common default
  password (see `weakPasswords` in `internal/server/auth.go`). Public keys
  are logged and refused. There is no sudo, su or useradd.

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

- **/proc is partial.** Each process has `cmdline`, `comm`, `stat`,
  `status`, `environ`, `maps`, `fd/`, `task/`, `exe`, `cwd` and `root`,
  but not the dozens of other files a real kernel has.
- **Pipelines run one stage after another**, not at once. Endless sources
  like `/dev/urandom` are handled by rules (`internal/shell/io.go`), not
  by real streaming.
- **The SSH handshake is Go's, not quite dropbear's.** The algorithm lists
  and host keys match dropbear 2019.78, but Go also offers
  `kex-strict-s-v00@openssh.com`, sends `ext-info`, lacks `kexguess2`, and
  lists auth methods as `password,publickey`. A fork of
  `golang.org/x/crypto/ssh` would fix that.

## Before you push

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

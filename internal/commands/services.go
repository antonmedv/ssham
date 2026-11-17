package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "crontab", Run: cmdCrontab},
		shell.Command{Name: "systemctl", Run: cmdSystemctl},
		shell.Command{Name: "service", Dir: "/usr/sbin", Run: cmdService},
		shell.Command{Name: "apt", Aliases: []string{"apt-get"}, Run: cmdApt},
		shell.Command{Name: "reboot", Aliases: []string{"shutdown", "poweroff", "halt"}, Dir: "/usr/sbin", Run: cmdReboot},
	)
}

func cmdCrontab(e *shell.Env) int {
	o := e.Flags("u")
	user := e.User().Name
	if u, ok := o.Value("u"); ok {
		if !e.User().IsRoot() && u != e.User().Name {
			fmt.Fprintf(e.Stderr, "must be privileged to use -u\n")
			return 1
		}
		user = u
	}
	p := "/var/spool/cron/crontabs/" + user
	switch {
	case o.Has("l"):
		data, err := e.FS.AsRoot().ReadFile(p)
		if err != nil || len(data) == 0 {
			fmt.Fprintf(e.Stderr, "no crontab for %s\n", user)
			return 1
		}
		e.Print(string(data))
		return 0
	case o.Has("r"):
		if err := e.FS.AsRoot().Remove(p, false); err != nil {
			fmt.Fprintf(e.Stderr, "no crontab for %s\n", user)
			return 1
		}
		return 0
	case o.Has("e"):
		fmt.Fprintf(e.Stderr, "no crontab for %s - using an empty one\n", user)
		fmt.Fprintln(e.Stderr, "crontab: \"/usr/bin/sensible-editor\" exited with status 1")
		return 1
	}
	var data string
	if len(o.Args) == 0 || o.Args[0] == "-" {
		data = e.ReadStdin()
	} else {
		b, err := e.FS.ReadFile(o.Args[0])
		if err != nil {
			fmt.Fprintf(e.Stderr, "%s: %s\n", o.Args[0], err)
			return 1
		}
		data = string(b)
	}
	e.Log(audit.CrontabInstall, "user", user, "content", truncate(data, 8192))
	_ = e.FS.AsRoot().WriteFile(p, []byte(data))
	return 0
}

func cmdSystemctl(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) == 0 {
		e.Print("  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION\n  cron.service                loaded active running Regular background program processing daemon\n  nginx.service               loaded active running A high performance web server and a reverse proxy server\n  ssh.service                 loaded active running OpenBSD Secure Shell server\n  systemd-journald.service    loaded active running Journal Service\n  systemd-resolved.service    loaded active running Network Name Resolution\n\n5 loaded units listed.\n")
		return 0
	}
	verb := o.Args[0]
	unit := ""
	if len(o.Args) > 1 {
		unit = strings.TrimSuffix(o.Args[1], ".service")
	}
	switch verb {
	case "status":
		if unit == "" {
			unit = "ssh"
		}
		e.Printf("● %s.service - %s\n     Loaded: loaded (/usr/lib/systemd/system/%s.service; enabled; preset: enabled)\n     Active: active (running) since %s; %s ago\n   Main PID: %d (%s)\n      Tasks: 1 (limit: 4613)\n     Memory: 4.2M (peak: 5.1M)\n        CPU: 213ms\n",
			unit, unit, unit, e.Host().Booted.Format("Mon 2006-01-02 15:04:05 MST"), uptimeString(e.Now().Sub(e.Host().Booted)), 700+len(unit)*13, unit)
		return 0
	case "start", "stop", "restart", "reload", "enable", "disable", "daemon-reload", "mask", "unmask":
		if !e.User().IsRoot() {
			fmt.Fprintf(e.Stderr, "Failed to %s %s.service: Interactive authentication required.\nSee system logs and 'systemctl status %s.service' for details.\n", verb, unit, unit)
			return 1
		}
		e.Log(audit.ServiceChange, "verb", verb, "unit", unit)
		if verb == "enable" {
			fmt.Fprintf(e.Stderr, "Created symlink /etc/systemd/system/multi-user.target.wants/%s.service → /etc/systemd/system/%s.service.\n", unit, unit)
		}
		return 0
	case "is-active":
		e.Print("active\n")
		return 0
	}
	return 0
}

func cmdService(e *shell.Env) int {
	if len(e.Args) < 3 {
		fmt.Fprintln(e.Stderr, "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]")
		return 1
	}
	return e.Run("systemctl", e.Args[2], e.Args[1])
}

func cmdApt(e *shell.Env) int {
	o := e.Flags("o")
	if len(o.Args) == 0 {
		e.Printf("%s 2.7.14 (amd64)\nUsage: %s [options] command\n", e.Args[0], e.Args[0])
		return 1
	}
	verb := o.Args[0]
	needRoot := map[string]bool{"install": true, "update": true, "upgrade": true, "remove": true, "purge": true, "autoremove": true, "dist-upgrade": true, "full-upgrade": true}
	if needRoot[verb] && !e.User().IsRoot() {
		fmt.Fprintln(e.Stderr, "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)")
		fmt.Fprintln(e.Stderr, "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?")
		return 100
	}
	switch verb {
	case "update":
		for _, l := range []string{
			"Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease",
			"Get:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease [126 kB]",
			"Hit:3 http://archive.ubuntu.com/ubuntu noble-backports InRelease",
			"Get:4 http://security.ubuntu.com/ubuntu noble-security InRelease [126 kB]",
			"Fetched 252 kB in 1s (318 kB/s)",
			"Reading package lists... Done",
		} {
			if !e.Sleep(time.Duration(200+e.Rand().IntN(400)) * time.Millisecond) {
				return 130
			}
			e.Printf("%s\n", l)
		}
	case "install":
		pkgs := o.Args[1:]
		e.Log(audit.PackageInstall, "packages", strings.Join(pkgs, " "))
		e.Print("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n")
		if !e.Sleep(800 * time.Millisecond) {
			return 130
		}
		for _, p := range pkgs {
			if strings.HasPrefix(p, "-") {
				continue
			}
			e.Printf("%s is already the newest version (%d.%d-%dubuntu%d).\n", p, 1+len(p)%4, len(p)%10, len(p)%3+1, len(p)%5)
		}
		e.Print("0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n")
	case "upgrade", "dist-upgrade", "full-upgrade":
		e.Print("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nCalculating upgrade... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
	case "list":
		e.Print("Listing... Done\n")
	default:
		e.Print("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n")
	}
	return 0
}

func cmdReboot(e *shell.Env) int {
	if !e.User().IsRoot() {
		fmt.Fprintln(e.Stderr, "Call to Reboot failed: Interactive authentication required.")
		return 1
	}
	e.Log(audit.Reboot, "command", strings.Join(e.Args, " "))
	fmt.Fprintf(e.Stderr, "\nBroadcast message from root@%s on pts/0 (%s):\n\nThe system will %s now!\n\n", e.Host().Hostname, e.Now().Format("Mon 2006-01-02 15:04:05 MST"), map[bool]string{true: "power off", false: "reboot"}[e.Args[0] == "shutdown" || e.Args[0] == "poweroff" || e.Args[0] == "halt"])
	e.Exit(0)
	return 0
}

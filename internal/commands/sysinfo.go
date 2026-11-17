package commands

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "uname", Usage: "[-amnrspvio]", Run: cmdUname},
		shell.Command{Name: "hostname", Usage: "[OPTIONS] [HOSTNAME | -F FILE]", Run: cmdHostname},
		shell.Command{Name: "uptime", Dir: "/usr/bin", Usage: "", Run: cmdUptime},
		shell.Command{Name: "free", Dir: "/usr/bin", Usage: "[-bkmgh]", Run: cmdFree},
		shell.Command{Name: "df", Usage: "[-PkmhTai] [-B SIZE] [FILESYSTEM]...", Run: cmdDf},
		shell.Command{Name: "mount", Usage: "[OPTIONS] [-o OPT] DEVICE NODE", Run: cmdMount},
		shell.Command{Name: "date", Usage: "[OPTIONS] [+FMT] [TIME]", Run: cmdDate},
		shell.Command{Name: "reboot", Dir: "/sbin", Usage: "[-d DELAY] [-n] [-f]", Run: cmdReboot},
		shell.Command{Name: "halt", Dir: "/sbin", Usage: "[-d DELAY] [-n] [-f] [-w]", Run: cmdReboot},
		shell.Command{Name: "poweroff", Dir: "/sbin", Usage: "[-d DELAY] [-n] [-f]", Run: cmdReboot},
	)
}

// zone is the device's time zone (TZ=CST-8 in /etc/TZ).
var zone = time.FixedZone("CST", 8*3600)

// hostname is kept in /proc/sys/kernel/hostname, so that changing it with
// hostname is seen by uname too.
func hostname(e *shell.Env) string {
	data, err := e.FS.AsRoot().ReadFile("/proc/sys/kernel/hostname")
	if err != nil {
		return e.Host().Hostname
	}
	return strings.TrimSpace(string(data))
}

func cmdUname(e *shell.Env) int {
	o := e.Flags()
	fields := []struct {
		flag, val string
		inAll     bool
	}{
		{"s", "Linux", true},
		{"n", hostname(e), true},
		{"r", e.Host().Kernel, true},
		{"v", "#1 Fri Mar 12 10:58:47 CST 2021", true},
		{"m", "armv7l", true},
		{"p", "unknown", false},
		{"i", "unknown", false},
		{"o", "GNU/Linux", true},
	}
	var out []string
	for _, f := range fields {
		if (o.Has("a") && f.inAll) || o.Has(f.flag) {
			out = append(out, f.val)
		}
	}
	if len(out) == 0 {
		out = []string{"Linux"}
	}
	e.Printf("%s\n", strings.Join(out, " "))
	return 0
}

func cmdHostname(e *shell.Env) int {
	o := e.Flags("F")
	name := ""
	switch {
	case o.Has("s"):
		h, _, _ := strings.Cut(hostname(e), ".")
		e.Printf("%s\n", h)
		return 0
	case o.Has("i"):
		e.Printf("%s\n", e.Host().IP)
		return 0
	case len(o.Args) > 0:
		name = o.Args[0]
	default:
		if f, ok := o.Value("F"); ok {
			data, err := e.FS.ReadFile(f)
			if err != nil {
				e.Errorf("can't open '%s': %s", f, err)
				return 1
			}
			name = strings.TrimSpace(string(data))
		}
	}
	if name == "" {
		e.Printf("%s\n", hostname(e))
		return 0
	}
	if !e.User().IsRoot() {
		e.Errorf("sethostname: Operation not permitted")
		return 1
	}
	_ = e.FS.AsRoot().WriteFile("/proc/sys/kernel/hostname", []byte(name+"\n"))
	return 0
}

func uptimeString(d time.Duration) string {
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	out := ""
	if days > 0 {
		out = fmt.Sprintf("%d days, ", days)
	}
	if h > 0 {
		return out + fmt.Sprintf("%2d:%02d", h, m)
	}
	return out + fmt.Sprintf("%d min", m)
}

func cmdUptime(e *shell.Env) int {
	up := e.Now().Sub(e.Host().Booted)
	l := rootfs.LoadAvg(e.Now())
	e.Printf(" %s up %s,  load average: %.2f, %.2f, %.2f\n", e.Now().In(zone).Format("15:04:05"), uptimeString(up), l[0], l[1], l[2])
	return 0
}

func cmdFree(e *shell.Env) int {
	o := e.Flags()
	f := func(kb int64) int64 {
		switch {
		case o.Has("m"):
			return kb / 1024
		case o.Has("g"):
			return kb / 1024 / 1024
		case o.Has("b"):
			return kb * 1024
		}
		return kb
	}
	m := meminfo(e)
	cache := m["Buffers"] + m["Cached"]
	e.Print("              total        used        free      shared  buff/cache   available\n")
	e.Printf("Mem:    %11d %11d %11d %11d %11d %11d\n", f(m["MemTotal"]), f(m["MemTotal"]-m["MemFree"]-cache), f(m["MemFree"]), f(m["Shmem"]), f(cache), f(m["MemAvailable"]))
	e.Printf("Swap:   %11d %11d %11d\n", f(0), f(0), f(0))
	return 0
}

func cmdDf(e *shell.Env) int {
	o := e.Flags("B")
	type fsys struct {
		name              string
		size, used, avail int64
		use               int
		mount             string
	}
	all := []fsys{
		{"/dev/root", 4416, 4416, 0, 100, "/"},
		{"tmpfs", 29528, 0, 29528, 0, "/dev"},
		{"tmpfs", 29528, 44, 29484, 0, "/tmp"},
		{"tmpfs", 29528, 28, 29500, 0, "/var"},
		{"/dev/mtdblock4", 1536, 476, 1060, 31, "/mnt/mtd"},
	}
	if o.Has("h") {
		e.Print("Filesystem                Size      Used Available Use% Mounted on\n")
		for _, f := range all {
			e.Printf("%-20s %9s %9s %9s %3d%% %s\n", f.name, dfHuman(f.size), dfHuman(f.used), dfHuman(f.avail), f.use, f.mount)
		}
		return 0
	}
	e.Print("Filesystem           1K-blocks      Used Available Use% Mounted on\n")
	for _, f := range all {
		e.Printf("%-20s %9d %9d %9d %3d%% %s\n", f.name, f.size, f.used, f.avail, f.use, f.mount)
	}
	return 0
}

// dfHuman formats kilobytes the way BusyBox df -h does: 5.0M, 44.0K, 0.
func dfHuman(kb int64) string {
	switch {
	case kb == 0:
		return "0"
	case kb < 1024:
		return fmt.Sprintf("%.1fK", float64(kb))
	}
	return fmt.Sprintf("%.1fM", float64(kb)/1024)
}

func cmdMount(e *shell.Env) int {
	if len(e.Args) > 1 {
		return e.Usage()
	}
	data, _ := e.FS.AsRoot().ReadFile("/proc/mounts")
	for _, l := range splitLines(string(data)) {
		f := strings.Fields(l)
		if len(f) >= 4 && f[0] != "rootfs" {
			e.Printf("%s on %s type %s (%s)\n", f[0], f[1], f[2], f[3])
		}
	}
	return 0
}

func cmdDate(e *shell.Env) int {
	now := e.Now().In(zone)
	for _, a := range e.Args[1:] {
		switch {
		case strings.HasPrefix(a, "+"):
			e.Printf("%s\n", strftime(a[1:], now))
			return 0
		case a == "-u":
			now = now.UTC()
		case a == "-R":
			e.Printf("%s\n", now.Format(time.RFC1123Z))
			return 0
		}
	}
	e.Printf("%s\n", now.Format("Mon Jan _2 15:04:05 MST 2006"))
	return 0
}

func strftime(f string, t time.Time) string {
	r := strings.NewReplacer(
		"%Y", t.Format("2006"), "%m", t.Format("01"), "%d", t.Format("02"), "%H", t.Format("15"),
		"%M", t.Format("04"), "%S", t.Format("05"), "%s", strconv.FormatInt(t.Unix(), 10),
		"%y", t.Format("06"), "%b", t.Format("Jan"), "%B", t.Format("January"), "%a", t.Format("Mon"),
		"%A", t.Format("Monday"), "%Z", t.Format("MST"), "%z", t.Format("-0700"), "%F", t.Format("2006-01-02"),
		"%T", t.Format("15:04:05"), "%D", t.Format("01/02/06"), "%e", t.Format("_2"), "%j", fmt.Sprintf("%03d", t.YearDay()),
		"%N", fmt.Sprintf("%09d", t.Nanosecond()), "%%", "%", "%n", "\n",
	)
	return r.Replace(f)
}

// cmdReboot ends the session, as a rebooting device drops the connection.
// BusyBox prints nothing.
func cmdReboot(e *shell.Env) int {
	if !e.User().IsRoot() {
		e.Errorf("Operation not permitted")
		return 1
	}
	e.Log(audit.Reboot, "command", strings.Join(e.Args, " "))
	e.Reboot()
	e.Exit(0)
	return 0
}

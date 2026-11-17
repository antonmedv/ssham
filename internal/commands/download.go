package commands

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/rootfs"
	"github.com/antonmedv/ssham/internal/shell"
)

// Nothing here touches the network. Downloads are logged and a placeholder
// file is written to the in-memory filesystem, so the operator can fetch
// the payload out-of-band.

func init() {
	register(
		shell.Command{Name: "wget", Dir: "/usr/bin", Usage: "[-c|--continue] [--spider] [-q|--quiet] [-O FILE] [-o LOGFILE]\n\t[--header 'header: value'] [-Y on/off] [-P DIR] [-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...", Run: cmdWget},
		shell.Command{Name: "tftp", Dir: "/usr/bin", Usage: "[OPTIONS] HOST [PORT]", Run: cmdTftp},
	)
}

// fakeIP returns a stable, plausible address for a hostname.
func fakeIP(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	h := fnv.New32a()
	h.Write([]byte(host))
	v := h.Sum32()
	return fmt.Sprintf("%d.%d.%d.%d", 23+v%180, (v>>8)%256, (v>>16)%256, 1+(v>>24)%253)
}

// archOf guesses which CPU a downloaded binary is for from its name, the
// way bots name their builds: bot.mips, bot.arm7, x86, ...
func archOf(name string) (machine uint16, bigEndian bool) {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "mpsl") || strings.Contains(n, "mipsel"):
		return 8, false
	case strings.Contains(n, "mips"):
		return 8, true
	case strings.Contains(n, "x86_64") || strings.Contains(n, "amd64"):
		return 62, false
	case strings.Contains(n, "x86") || strings.Contains(n, "i686") || strings.Contains(n, "i586") || strings.Contains(n, "i386"):
		return 3, false
	case strings.Contains(n, "ppc") || strings.Contains(n, "powerpc"):
		return 20, true
	case strings.Contains(n, "sh4"):
		return 42, false
	case strings.Contains(n, "aarch64") || strings.Contains(n, "arm64"):
		return 183, false
	}
	return 40, false // arm, or unknown
}

// payload returns placeholder content for a downloaded file: a script
// header for .sh files, otherwise a binary for the CPU its name suggests,
// of plausible size (wget reports that size and ls shows it).
func payload(e *shell.Env, name string) []byte {
	if strings.HasSuffix(name, ".sh") {
		return []byte("#!/bin/sh\n")
	}
	b := make([]byte, 20_000+e.Rand().IntN(100_000))
	for i := range b {
		b[i] = byte(e.Rand().Uint32())
	}
	copy(b, rootfs.Binary(int64(len(b))).Data)
	machine, big := archOf(name)
	if big {
		b[5] = 2
		binary.BigEndian.PutUint16(b[18:], machine)
	} else {
		binary.LittleEndian.PutUint16(b[18:], machine)
	}
	return b
}

// cmdWget is BusyBox wget: plain http and ftp only.
func cmdWget(e *shell.Env) int {
	o := e.Flags("O", "o", "P", "U", "T", "Y", "header", "user-agent", "output-document")
	if len(o.Args) == 0 {
		return e.Usage()
	}
	quiet := o.Has("q", "quiet")
	out, hasOut := o.Value("O", "output-document")
	dir, _ := o.Value("P")
	status := 0
	for _, raw := range o.Args {
		target := raw
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		u, err := url.Parse(target)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "ftp") {
			e.Log(audit.Download, "tool", "wget", "url", raw, "dest", "")
			e.Errorf("not an http or ftp url: %s", raw)
			status = 1
			continue
		}
		name := path.Base(u.Path)
		if name == "/" || name == "." || name == "" {
			name = "index.html"
		}
		if hasOut {
			name = out
		} else if dir != "" {
			name = path.Join(dir, name)
		}
		e.Log(audit.Download, "tool", "wget", "url", u.String(), "dest", name)
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "ftp": "21"}[u.Scheme]
		}
		if !quiet {
			fmt.Fprintf(e.Stderr, "Connecting to %s (%s:%s)\n", u.Hostname(), fakeIP(u.Hostname()), port)
		}
		if !e.Sleep(time.Duration(300+e.Rand().IntN(700)) * time.Millisecond) {
			return 1
		}
		data := payload(e, path.Base(u.Path))
		if name == "-" {
			_, _ = e.Stdout.Write(data)
			continue
		}
		if err := e.FS.WriteFile(name, data); err != nil {
			e.Errorf("can't open '%s': %s", name, err)
			status = 1
			continue
		}
		if !quiet {
			fmt.Fprintf(e.Stderr, "saving to '%s'\n%-20s 100%% |********************************| %5s  0:00:00 ETA\n'%s' saved\n",
				name, path.Base(name), wgetSize(len(data)), name)
		}
	}
	return status
}

// wgetSize formats a size the way BusyBox's progress bar does: 27416, 119k.
func wgetSize(n int) string {
	if n < 100000 {
		return fmt.Sprint(n)
	}
	return fmt.Sprintf("%dk", n/1024)
}

// cmdTftp is BusyBox tftp: tftp -g -r REMOTE [-l LOCAL] HOST [PORT]. It
// prints nothing on success.
func cmdTftp(e *shell.Env) int {
	o := e.Flags("l", "r", "b")
	if len(o.Args) == 0 || (!o.Has("g") && !o.Has("p")) {
		return e.Usage()
	}
	host := o.Args[0]
	remote, _ := o.Value("r")
	local, hasLocal := o.Value("l")
	if !hasLocal {
		local = path.Base(remote)
	}
	if remote == "" {
		remote = local
	}
	if o.Has("p") { // upload: nothing to do but log it
		e.Log(audit.Download, "tool", "tftp-put", "url", "tftp://"+host+"/"+remote, "dest", local)
		return 0
	}
	e.Log(audit.Download, "tool", "tftp", "url", "tftp://"+host+"/"+remote, "dest", local)
	if !e.Sleep(time.Duration(500+e.Rand().IntN(1500)) * time.Millisecond) {
		return 1
	}
	if err := e.FS.WriteFile(local, payload(e, remote)); err != nil {
		e.Errorf("can't open '%s': %s", local, err)
		return 1
	}
	return 0
}

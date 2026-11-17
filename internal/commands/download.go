package commands

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

// Nothing here touches the network: see net.go. Every attempt is logged,
// so the operator can fetch the payload out-of-band.

func init() {
	register(
		shell.Command{Name: "wget", Dir: "/usr/bin", Usage: "[-c|--continue] [--spider] [-q|--quiet] [-O FILE] [-o LOGFILE]\n\t[--header 'header: value'] [-Y on/off] [-P DIR] [-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...", Run: cmdWget},
		shell.Command{Name: "tftp", Dir: "/usr/bin", Usage: "[OPTIONS] HOST [PORT]", Run: cmdTftp},
	)
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
		ip, kind, ok := resolve(e, u.Hostname())
		if !ok {
			e.Errorf("bad address '%s'", u.Hostname())
			status = 1
			continue
		}
		if !quiet {
			fmt.Fprintf(e.Stderr, "Connecting to %s (%s:%s)\n", u.Hostname(), ip, port)
		}
		data, err := wgetFetch(e, kind, ip, port, u)
		if err != nil {
			e.Errorf("%s", err)
			status = 1
			continue
		}
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

// wgetFetch is what the camera's network gives wget: its own web server
// and the router's login page answer, everything else fails.
func wgetFetch(e *shell.Env, kind hostKind, ip, port string, u *url.URL) ([]byte, error) {
	switch kind {
	case hostOutside:
		e.Sleep(connectTimeout)
		return nil, fmt.Errorf("can't connect to remote host (%s): Connection timed out", ip)
	case hostLAN:
		e.Sleep(arpTimeout)
		return nil, fmt.Errorf("can't connect to remote host (%s): No route to host", ip)
	case hostGateway:
		if port == "80" && u.Scheme == "http" {
			return nil, fmt.Errorf("server returned error: HTTP/1.1 401 Unauthorized")
		}
	case hostSelf:
		switch {
		case port == "22":
			return nil, fmt.Errorf("server returned error: SSH-2.0-dropbear_2019.78")
		case port == "80" && u.Scheme == "http":
			p := path.Clean("/" + u.Path)
			if p == "/" {
				p = "/index.html"
			}
			data, err := e.FS.AsRoot().ReadFile("/app/www" + p)
			if err != nil {
				return nil, fmt.Errorf("server returned error: HTTP/1.1 404 Not Found")
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("can't connect to remote host (%s): Connection refused", ip)
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
	tool := "tftp"
	if o.Has("p") {
		tool = "tftp-put"
	}
	e.Log(audit.Download, "tool", tool, "url", "tftp://"+host+"/"+remote, "dest", local)
	if _, _, ok := resolve(e, host); !ok {
		e.Errorf("bad address '%s'", host)
		return 1
	}
	if o.Has("p") {
		if _, err := e.FS.ReadFile(local); err != nil {
			e.Errorf("can't open '%s': %s", local, err)
			return 1
		}
	} else {
		if err := e.FS.WriteFile(local, nil); err != nil {
			e.Errorf("can't open '%s': %s", local, err)
			return 1
		}
		defer func() { _ = e.FS.Remove(local, false) }()
	}
	// No server answers: tftp retries for a while, then gives up and
	// removes the file it created.
	e.Sleep(15 * time.Second)
	e.Errorf("timeout")
	return 1
}

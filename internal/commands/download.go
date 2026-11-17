package commands

import (
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/audit"
	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "wget", Run: cmdWget},
		shell.Command{Name: "curl", Run: cmdCurl},
	)
}

func cmdWget(e *shell.Env) int {
	o := e.Flags("O", "o", "P", "U", "t", "T", "output-document", "directory-prefix", "user-agent", "tries", "timeout", "header")
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.")
		return 1
	}
	quiet := o.Has("q", "quiet")
	out, hasOut := o.Value("O", "output-document")
	dir, _ := o.Value("P", "directory-prefix")
	status := 0
	for _, raw := range o.Args {
		u, ok := parseURL(raw)
		if !ok {
			fmt.Fprintf(e.Stderr, "%s: Invalid URL %s: Unsupported scheme\n", raw, raw)
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
		ip := fakeIP(u.Hostname())
		now := e.Now().Format("2006-01-02 15:04:05")
		if !quiet {
			fmt.Fprintf(e.Stderr, "--%s--  %s\nResolving %s (%s)... %s\nConnecting to %s (%s)|%s|:%s... ", now, u.String(), u.Hostname(), u.Hostname(), ip, u.Hostname(), u.Hostname(), ip, portOf(u))
		}
		if !e.Sleep(time.Duration(300+e.Rand().IntN(700)) * time.Millisecond) {
			return 130
		}
		body, isIP := ipEcho(u)
		data := []byte(body)
		if !isIP {
			data = payload(e, path.Base(u.Path))
		}
		size := len(data)
		if !quiet {
			fmt.Fprintf(e.Stderr, "connected.\nHTTP request sent, awaiting response... 200 OK\nLength: %d (%s) [application/octet-stream]\nSaving to: ‘%s’\n\n", size, humanSize(int64(size)), name)
		}
		if !e.Sleep(time.Duration(400+e.Rand().IntN(1200)) * time.Millisecond) {
			return 130
		}
		if name == "-" {
			_, _ = e.Stdout.Write(data)
		} else if err := e.FS.WriteFile(name, data); err != nil {
			fmt.Fprintf(e.Stderr, "%s: %s\n", name, err)
			status = 1
			continue
		}
		if !quiet {
			fmt.Fprintf(e.Stderr, "%-20s 100%%[===================>] %7s  %s/s    in 0.%ds   \n\n%s (%s/s) - ‘%s’ saved [%d/%d]\n\n",
				path.Base(name), humanSize(int64(size)), humanSize(int64(size*3)), 1+e.Rand().IntN(9), e.Now().Format("2006-01-02 15:04:05"), humanSize(int64(size*3)), name, size, size)
		}
	}
	return status
}

func cmdCurl(e *shell.Env) int {
	o := e.Flags("o", "X", "H", "d", "A", "u", "m", "x", "e", "b", "c", "T", "F", "w",
		"output", "request", "header", "data", "user-agent", "user", "max-time", "proxy", "connect-timeout", "data-raw", "data-binary", "retry", "write-out")
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "curl: try 'curl --help' or 'curl --manual' for more information")
		return 2
	}
	silent := o.Has("s", "silent")
	status := 0
	for _, raw := range o.Args {
		u, ok := parseURL(raw)
		if !ok {
			fmt.Fprintf(e.Stderr, "curl: (3) URL rejected: Malformed input to a URL function\n")
			status = 3
			continue
		}
		dest, hasDest := o.Value("o", "output")
		if o.Has("O", "remote-name") {
			dest, hasDest = path.Base(u.Path), true
		}
		data, _ := o.Value("d", "data", "data-raw", "data-binary")
		e.Log(audit.Download, "tool", "curl", "url", u.String(), "dest", dest, "post_data", data)
		if !e.Sleep(time.Duration(200+e.Rand().IntN(600)) * time.Millisecond) {
			return 130
		}
		body, isIP := ipEcho(u)
		content := []byte(body)
		if !isIP {
			content = payload(e, path.Base(u.Path))
		}
		if o.Has("I", "head") {
			e.Printf("HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", e.Now().UTC().Format(time.RFC1123), len(content))
			continue
		}
		if !isIP {
			if !hasDest {
				// Printing a binary to the terminal is what curl refuses to do.
				if e.IsTTY() && content[0] == 0x7f {
					fmt.Fprintln(e.Stderr, "Warning: Binary output can mess up your terminal. Use \"--output -\" to tell \nWarning: curl to output it to your terminal anyway, or consider \"--output \nWarning: <FILE>\" to save to a file.")
					status = 23
					continue
				}
				if strings.HasSuffix(u.Path, ".sh") || u.Path == "" || u.Path == "/" {
					content = nil
				}
			}
		}
		if hasDest && dest != "-" {
			if !silent && !e.IsTTY() {
				// progress meter only goes to a terminal
			} else if !silent {
				fmt.Fprintf(e.Stderr, "  %% Total    %% Received %% Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100 %5s  100 %5s    0     0  %5s      0 --:--:-- --:--:-- --:--:-- %5s\n",
					humanSize(int64(len(content))), humanSize(int64(len(content))), humanSize(int64(len(content)*4)), humanSize(int64(len(content)*4)))
			}
			if err := e.FS.WriteFile(dest, content); err != nil {
				fmt.Fprintf(e.Stderr, "curl: (23) Failure writing output to destination\n")
				status = 23
			}
			continue
		}
		_, _ = e.Stdout.Write(content)
	}
	return status
}

const publicIP = "18.197.42.103"

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

func parseURL(raw string) (*url.URL, bool) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, false
	}
	return u, true
}

// payload returns placeholder content for a downloaded file.
func payload(e *shell.Env, name string) []byte {
	if strings.HasSuffix(name, ".sh") {
		return []byte("#!/bin/sh\n")
	}
	if strings.HasSuffix(name, ".html") || strings.HasSuffix(name, ".htm") || name == "index.html" {
		return []byte("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>\n")
	}
	// A fake executable of plausible size (its size is what wget reports
	// and ls shows, so they must agree).
	b := make([]byte, 20_000+e.Rand().IntN(180_000))
	for i := range b {
		b[i] = byte(e.Rand().Uint32())
	}
	copy(b, "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00")
	return b
}

func ipEcho(u *url.URL) (string, bool) {
	switch strings.ToLower(u.Hostname()) {
	case "ifconfig.me", "icanhazip.com", "api.ipify.org", "ipinfo.io", "ifconfig.co", "ipecho.net", "checkip.amazonaws.com", "ident.me", "myip.dnsomatic.com":
		if strings.HasPrefix(u.Path, "/json") || (u.Hostname() == "ipinfo.io" && u.Path == "") {
			return fmt.Sprintf("{\n  \"ip\": \"%s\",\n  \"hostname\": \"ec2-%s.eu-central-1.compute.amazonaws.com\",\n  \"city\": \"Frankfurt am Main\",\n  \"region\": \"Hesse\",\n  \"country\": \"DE\",\n  \"org\": \"AS16509 Amazon.com, Inc.\"\n}", publicIP, strings.ReplaceAll(publicIP, ".", "-")), true
		}
		return publicIP + "\n", true
	}
	return "", false
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

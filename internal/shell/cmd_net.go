package shell

import (
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/url"
	"path"
	"strings"
	"time"
)

// None of these commands touch the network. Downloads are logged and a
// placeholder file is written to the virtual filesystem, so the operator can
// fetch the payload out-of-band if desired.

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
func payload(name string) []byte {
	if strings.HasSuffix(name, ".sh") {
		return []byte("#!/bin/sh\n")
	}
	if strings.HasSuffix(name, ".html") || strings.HasSuffix(name, ".htm") || name == "index.html" {
		return []byte("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>\n")
	}
	b := make([]byte, 0, 64)
	b = append(b, "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00"...)
	for i := 0; i < 40; i++ {
		b = append(b, byte(rand.IntN(256)))
	}
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

func cmdWget(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "O", "o", "P", "U", "t", "T", "output-document", "directory-prefix", "user-agent", "tries", "timeout", "header")
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.")
		return 1
	}
	quiet := o.has("q", "quiet")
	out, hasOut := o.val("O", "output-document")
	dir, _ := o.val("P", "directory-prefix")
	status := 0
	for _, raw := range o.pos {
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
		s.log.Event("download", "tool", "wget", "url", u.String(), "dest", name)
		ip := fakeIP(u.Hostname())
		now := time.Now().Format("2006-01-02 15:04:05")
		if !quiet {
			fmt.Fprintf(e.Stderr, "--%s--  %s\nResolving %s (%s)... %s\nConnecting to %s (%s)|%s|:%s... ", now, u.String(), u.Hostname(), u.Hostname(), ip, u.Hostname(), u.Hostname(), ip, portOf(u))
		}
		if !e.Sleep(time.Duration(300+rand.IntN(700)) * time.Millisecond) {
			return 130
		}
		body, isIP := ipEcho(u)
		data := []byte(body)
		if !isIP {
			data = payload(path.Base(name))
		}
		size := len(data)
		if !isIP && len(data) > 32 {
			size = 50000 + rand.IntN(2000000)
		}
		if !quiet {
			fmt.Fprintf(e.Stderr, "connected.\nHTTP request sent, awaiting response... 200 OK\nLength: %d (%s) [application/octet-stream]\nSaving to: ‘%s’\n\n", size, humanSize(int64(size)), name)
		}
		if !e.Sleep(time.Duration(400+rand.IntN(1200)) * time.Millisecond) {
			return 130
		}
		if name == "-" {
			_, _ = e.Stdout.Write(data)
		} else if err := s.fs.WriteFile(s.user, s.resolve(name), data, false); err != nil {
			fmt.Fprintf(e.Stderr, "%s: %s\n", name, err)
			status = 1
			continue
		}
		if !quiet {
			fmt.Fprintf(e.Stderr, "%-20s 100%%[===================>] %7s  %s/s    in 0.%ds   \n\n%s (%s/s) - ‘%s’ saved [%d/%d]\n\n",
				path.Base(name), humanSize(int64(size)), humanSize(int64(size*3)), 1+rand.IntN(9), time.Now().Format("2006-01-02 15:04:05"), humanSize(int64(size*3)), name, size, size)
		}
	}
	return status
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

func cmdCurl(e *Env) int {
	s := e.sh
	o := getopt(e.Args[1:], "o", "X", "H", "d", "A", "u", "m", "x", "e", "b", "c", "T", "F", "w",
		"output", "request", "header", "data", "user-agent", "user", "max-time", "proxy", "connect-timeout", "data-raw", "data-binary", "retry", "write-out")
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "curl: try 'curl --help' or 'curl --manual' for more information")
		return 2
	}
	silent := o.has("s", "silent")
	status := 0
	for _, raw := range o.pos {
		u, ok := parseURL(raw)
		if !ok {
			fmt.Fprintf(e.Stderr, "curl: (3) URL rejected: Malformed input to a URL function\n")
			status = 3
			continue
		}
		dest, hasDest := o.val("o", "output")
		if o.has("O", "remote-name") {
			dest, hasDest = path.Base(u.Path), true
		}
		data, _ := o.val("d", "data", "data-raw", "data-binary")
		s.log.Event("download", "tool", "curl", "url", u.String(), "dest", dest, "post_data", data)
		if !e.Sleep(time.Duration(200+rand.IntN(600)) * time.Millisecond) {
			return 130
		}
		body, isIP := ipEcho(u)
		content := []byte(body)
		if !isIP {
			content = payload(path.Base(u.Path))
			if !hasDest {
				// Printing a binary to the terminal is what curl refuses to do.
				if e.isTTY() && content[0] == 0x7f {
					fmt.Fprintln(e.Stderr, "Warning: Binary output can mess up your terminal. Use \"--output -\" to tell \nWarning: curl to output it to your terminal anyway, or consider \"--output \nWarning: <FILE>\" to save to a file.")
					status = 23
					continue
				}
				if strings.HasSuffix(u.Path, ".sh") || u.Path == "" || u.Path == "/" {
					content = nil
				}
			}
		}
		if o.has("I", "head") {
			e.Printf("HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", time.Now().UTC().Format(time.RFC1123), len(content))
			continue
		}
		if hasDest && dest != "-" {
			if !silent && !e.isTTY() {
				// progress meter only goes to a terminal
			} else if !silent {
				fmt.Fprintf(e.Stderr, "  %% Total    %% Received %% Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100 %5s  100 %5s    0     0  %5s      0 --:--:-- --:--:-- --:--:-- %5s\n",
					humanSize(int64(len(content))), humanSize(int64(len(content))), humanSize(int64(len(content)*4)), humanSize(int64(len(content)*4)))
			}
			if err := s.fs.WriteFile(s.user, s.resolve(dest), content, false); err != nil {
				fmt.Fprintf(e.Stderr, "curl: (23) Failure writing output to destination\n")
				status = 23
			}
			continue
		}
		_, _ = e.Stdout.Write(content)
	}
	return status
}

func cmdPing(e *Env) int {
	o := getopt(e.Args[1:], "c", "i", "W", "w", "s", "t", "I")
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "ping: usage error: Destination address required")
		return 1
	}
	host := o.pos[0]
	count := -1
	if c, ok := o.val("c"); ok {
		fmt.Sscan(c, &count)
	}
	ip := fakeIP(host)
	base := 8 + rand.Float64()*30
	e.Printf("PING %s (%s) 56(84) bytes of data.\n", host, ip)
	sent := 0
	var total float64
	start := time.Now()
	for count < 0 || sent < count {
		rtt := base + rand.Float64()*2
		if sent > 0 && !e.Sleep(time.Second) {
			break
		}
		sent++
		total += rtt
		name := host
		if name != ip {
			name = fmt.Sprintf("%s (%s)", host, ip)
		}
		e.Printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", name, sent, 50+len(host)%10, rtt)
	}
	if e.Ctx.Err() != nil {
		e.Print("^C")
	}
	e.Printf("\n--- %s ping statistics ---\n%d packets transmitted, %d received, 0%% packet loss, time %dms\n", host, sent, sent, time.Since(start).Milliseconds())
	if sent > 0 {
		avg := total / float64(sent)
		e.Printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", base, avg, base+2, 0.4)
	}
	if e.Ctx.Err() != nil {
		return 130
	}
	return 0
}

func cmdIfconfig(e *Env) int {
	e.Print(`docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:7c:1e:9a:3f  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        TX packets 0  bytes 0 (0.0 B)

ens5: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::8a3:5ff:fe2c:7d41  prefixlen 64  scopeid 0x20<link>
        ether 0a:a3:05:2c:7d:41  txqueuelen 1000  (Ethernet)
        RX packets 1849273  bytes 1247795346 (1.2 GB)
        TX packets 1102484  bytes 312094882 (312.0 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 18472  bytes 1931223 (1.9 MB)
        TX packets 18472  bytes 1931223 (1.9 MB)

`)
	return 0
}

func cmdIP(e *Env) int {
	obj := ""
	for _, a := range e.Args[1:] {
		if !strings.HasPrefix(a, "-") {
			obj = a
			break
		}
	}
	switch {
	case strings.HasPrefix(obj, "a"):
		e.Print(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 0a:a3:05:2c:7d:41 brd ff:ff:ff:ff:ff:ff
    altname enp0s5
    inet 10.0.2.15/24 metric 100 brd 10.0.2.255 scope global dynamic ens5
       valid_lft 2845sec preferred_lft 2845sec
    inet6 fe80::8a3:5ff:fe2c:7d41/64 scope link
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:7c:1e:9a:3f brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
`)
	case strings.HasPrefix(obj, "r"):
		e.Print("default via 10.0.2.1 dev ens5 proto dhcp src 10.0.2.15 metric 100\n10.0.2.0/24 dev ens5 proto kernel scope link src 10.0.2.15 metric 100\n172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n")
	case strings.HasPrefix(obj, "l"):
		e.Print("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP mode DEFAULT group default qlen 1000\n    link/ether 0a:a3:05:2c:7d:41 brd ff:ff:ff:ff:ff:ff\n")
	case obj == "":
		fmt.Fprintln(e.Stderr, "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\nwhere  OBJECT := { address | link | neigh | route | rule | tunnel | ... }")
		return 255
	}
	return 0
}

func cmdNetstat(e *Env) int {
	s := e.sh
	header := "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State      "
	if e.Args[0] == "ss" {
		e.Print("Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n")
		e.Print("tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*\ntcp   LISTEN 0      511          0.0.0.0:80          0.0.0.0:*\ntcp   LISTEN 0      4096         0.0.0.0:22          0.0.0.0:*\ntcp   LISTEN 0      151        127.0.0.1:3306        0.0.0.0:*\n")
		e.Printf("tcp   ESTAB  0      0          10.0.2.15:22   %15s:%d\n", s.cfg.ClientIP, 50000+s.pid%10000)
		return 0
	}
	withProg := strings.Contains(strings.Join(e.Args[1:], ""), "p")
	if withProg {
		header += "PID/Program name    "
	}
	e.Printf("%s\n", header)
	rows := [][3]string{
		{"127.0.0.53:53", "0.0.0.0:*", "512/systemd-resolve"},
		{"0.0.0.0:80", "0.0.0.0:*", "745/nginx: master p"},
		{"0.0.0.0:22", "0.0.0.0:*", "702/sshd: /usr/sbin"},
		{"127.0.0.1:3306", "0.0.0.0:*", "-"},
	}
	for _, r := range rows {
		prog := ""
		if withProg {
			prog = r[2]
			if s.uid != 0 {
				prog = "-"
			}
		}
		e.Printf("tcp        0      0 %-23s %-23s LISTEN      %s\n", r[0], r[1], prog)
	}
	return 0
}

func cmdSSH(e *Env) int {
	o := getopt(e.Args[1:], "p", "i", "l", "o", "F", "L", "R", "D", "J")
	if len(o.pos) == 0 {
		fmt.Fprintln(e.Stderr, "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]\n           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n           destination [command [argument ...]]")
		return 255
	}
	if o.has("V") {
		fmt.Fprintln(e.Stderr, "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024")
		return 0
	}
	target := o.pos[0]
	host := target
	if i := strings.LastIndexByte(target, '@'); i >= 0 {
		host = target[i+1:]
	}
	port, ok := o.val("p")
	if !ok {
		port = "22"
	}
	e.sh.log.Event("lateral_movement", "tool", e.Args[0], "target", target, "port", port, "args", strings.Join(e.Args[1:], " "))
	if !e.Sleep(time.Duration(8+rand.IntN(5)) * time.Second) {
		return 255
	}
	if e.Args[0] == "scp" {
		fmt.Fprintf(e.Stderr, "ssh: connect to host %s port %s: Connection timed out\nscp: Connection closed\n", host, port)
		return 255
	}
	fmt.Fprintf(e.Stderr, "ssh: connect to host %s port %s: Connection timed out\n", host, port)
	return 255
}

func cmdNc(e *Env) int {
	o := getopt(e.Args[1:], "w", "p", "s", "e", "c")
	e.sh.log.Event("network_tool", "tool", e.Args[0], "args", strings.Join(e.Args[1:], " "))
	if o.has("l") {
		// Listening: block until interrupted.
		for e.Sleep(time.Hour) {
		}
		return 130
	}
	if len(o.pos) < 2 {
		if e.Args[0] == "telnet" && len(o.pos) == 1 {
			o.pos = append(o.pos, "23")
		} else {
			fmt.Fprintln(e.Stderr, "usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n\t  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]\n\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n\t  [destination] [port]")
			return 1
		}
	}
	if !e.Sleep(time.Duration(1+rand.IntN(3)) * time.Second) {
		return 130
	}
	if e.Args[0] == "telnet" {
		e.Printf("Trying %s...\n", fakeIP(o.pos[0]))
		fmt.Fprintf(e.Stderr, "telnet: Unable to connect to remote host: Connection refused\n")
		return 1
	}
	if o.has("v", "z") {
		fmt.Fprintf(e.Stderr, "nc: connect to %s port %s (tcp) failed: Connection refused\n", o.pos[0], o.pos[1])
	}
	return 1
}

func cmdIptables(e *Env) int {
	if e.sh.uid != 0 {
		fmt.Fprintf(e.Stderr, "iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)\n")
		return 4
	}
	e.sh.log.Event("firewall_change", "args", strings.Join(e.Args[1:], " "))
	if len(e.Args) > 1 && (e.Args[1] == "-L" || e.Args[1] == "-nL" || e.Args[1] == "-S") {
		e.Print("Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination         \n\nChain FORWARD (policy DROP)\ntarget     prot opt source               destination         \n\nChain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination         \n")
	}
	return 0
}

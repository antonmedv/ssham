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
		shell.Command{Name: "ping", Run: cmdPing},
		shell.Command{Name: "ifconfig", Dir: "/usr/sbin", Run: cmdIfconfig},
		shell.Command{Name: "ip", Run: cmdIP},
		shell.Command{Name: "netstat", Aliases: []string{"ss"}, Run: cmdNetstat},
		shell.Command{Name: "ssh", Aliases: []string{"scp"}, Run: cmdSSH},
		shell.Command{Name: "nc", Aliases: []string{"telnet"}, Run: cmdNc},
		shell.Command{Name: "iptables", Dir: "/usr/sbin", Run: cmdIptables},
	)
}

func cmdPing(e *shell.Env) int {
	o := e.Flags("c", "i", "W", "w", "s", "t", "I")
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "ping: usage error: Destination address required")
		return 1
	}
	host := o.Args[0]
	count := -1
	if c, ok := o.Value("c"); ok {
		fmt.Sscan(c, &count)
	}
	ip := fakeIP(host)
	base := 8 + e.Rand().Float64()*30
	e.Printf("PING %s (%s) 56(84) bytes of data.\n", host, ip)
	sent := 0
	var total float64
	start := e.Now()
	for count < 0 || sent < count {
		rtt := base + e.Rand().Float64()*2
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
	e.Printf("\n--- %s ping statistics ---\n%d packets transmitted, %d received, 0%% packet loss, time %dms\n", host, sent, sent, e.Now().Sub(start).Milliseconds())
	if sent > 0 {
		avg := total / float64(sent)
		e.Printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", base, avg, base+2, 0.4)
	}
	if e.Ctx.Err() != nil {
		return 130
	}
	return 0
}

func cmdIfconfig(e *shell.Env) int {
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

func cmdIP(e *shell.Env) int {
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

func cmdNetstat(e *shell.Env) int {
	header := "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State      "
	if e.Args[0] == "ss" {
		e.Print("Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n")
		e.Print("tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*\ntcp   LISTEN 0      511          0.0.0.0:80          0.0.0.0:*\ntcp   LISTEN 0      4096         0.0.0.0:22          0.0.0.0:*\ntcp   LISTEN 0      151        127.0.0.1:3306        0.0.0.0:*\n")
		e.Printf("tcp   ESTAB  0      0          10.0.2.15:22   %15s:%d\n", e.Session().ClientIP, 50000+e.Session().PID%10000)
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
			if !e.User().IsRoot() {
				prog = "-"
			}
		}
		e.Printf("tcp        0      0 %-23s %-23s LISTEN      %s\n", r[0], r[1], prog)
	}
	return 0
}

func cmdSSH(e *shell.Env) int {
	o := e.Flags("p", "i", "l", "o", "F", "L", "R", "D", "J")
	if len(o.Args) == 0 {
		fmt.Fprintln(e.Stderr, "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]\n           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n           destination [command [argument ...]]")
		return 255
	}
	if o.Has("V") {
		fmt.Fprintln(e.Stderr, "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024")
		return 0
	}
	target := o.Args[0]
	if e.Args[0] == "scp" {
		// scp src user@host:path: the host is in the argument with a colon.
		for _, a := range o.Args {
			if host, _, ok := strings.Cut(a, ":"); ok {
				target = host
			}
		}
	}
	host := target
	if i := strings.LastIndexByte(target, '@'); i >= 0 {
		host = target[i+1:]
	}
	port, ok := o.Value("p")
	if !ok {
		port = "22"
	}
	e.Log(audit.LateralMovement, "tool", e.Args[0], "target", target, "port", port, "args", strings.Join(e.Args[1:], " "))
	if !e.Sleep(time.Duration(8+e.Rand().IntN(5)) * time.Second) {
		return 255
	}
	if e.Args[0] == "scp" {
		fmt.Fprintf(e.Stderr, "ssh: connect to host %s port %s: Connection timed out\nscp: Connection closed\n", host, port)
		return 255
	}
	fmt.Fprintf(e.Stderr, "ssh: connect to host %s port %s: Connection timed out\n", host, port)
	return 255
}

func cmdNc(e *shell.Env) int {
	o := e.Flags("w", "p", "s", "e", "c")
	e.Log(audit.NetworkTool, "tool", e.Args[0], "args", strings.Join(e.Args[1:], " "))
	if o.Has("l") {
		// Listening: block until interrupted.
		for e.Sleep(time.Hour) {
		}
		return 130
	}
	if len(o.Args) < 2 {
		if e.Args[0] == "telnet" && len(o.Args) == 1 {
			o.Args = append(o.Args, "23")
		} else {
			fmt.Fprintln(e.Stderr, "usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n\t  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]\n\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n\t  [destination] [port]")
			return 1
		}
	}
	if !e.Sleep(time.Duration(1+e.Rand().IntN(3)) * time.Second) {
		return 130
	}
	if e.Args[0] == "telnet" {
		e.Printf("Trying %s...\n", fakeIP(o.Args[0]))
		fmt.Fprintf(e.Stderr, "telnet: Unable to connect to remote host: Connection refused\n")
		return 1
	}
	if o.Has("v", "z") {
		fmt.Fprintf(e.Stderr, "nc: connect to %s port %s (tcp) failed: Connection refused\n", o.Args[0], o.Args[1])
	}
	return 1
}

func cmdIptables(e *shell.Env) int {
	if !e.User().IsRoot() {
		fmt.Fprintf(e.Stderr, "iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)\n")
		return 4
	}
	e.Log(audit.FirewallChange, "args", strings.Join(e.Args[1:], " "))
	if len(e.Args) > 1 && (e.Args[1] == "-L" || e.Args[1] == "-nL" || e.Args[1] == "-S") {
		e.Print("Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination         \n\nChain FORWARD (policy DROP)\ntarget     prot opt source               destination         \n\nChain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination         \n")
	}
	return 0
}

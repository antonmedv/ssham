package commands

import (
	"fmt"
	"time"

	"github.com/antonmedv/ssham/internal/shell"
)

func init() {
	register(
		shell.Command{Name: "ping", Usage: "[OPTIONS] HOST", Run: cmdPing},
		shell.Command{Name: "ifconfig", Dir: "/sbin", Usage: "[-a] interface [address]", Run: cmdIfconfig},
		shell.Command{Name: "netstat", Usage: "[-ral] [-tuwx] [-enWp]", Run: cmdNetstat},
		shell.Command{Name: "route", Dir: "/sbin", Usage: "[{add|del|delete}]", Run: cmdRoute},
	)
}

func cmdPing(e *shell.Env) int {
	o := e.Flags("c", "i", "W", "w", "s", "t", "I")
	if len(o.Args) == 0 {
		return e.Usage()
	}
	host := o.Args[0]
	count := -1
	if c, ok := o.Value("c"); ok {
		fmt.Sscan(c, &count)
	}
	ip := fakeIP(host)
	base := 8 + e.Rand().Float64()*30
	e.Printf("PING %s (%s): 56 data bytes\n", host, ip)
	sent := 0
	minRTT, maxRTT, total := 1e9, 0.0, 0.0
	for count < 0 || sent < count {
		if sent > 0 && !e.Sleep(time.Second) {
			break
		}
		rtt := base + e.Rand().Float64()*2
		minRTT, maxRTT, total = min(minRTT, rtt), max(maxRTT, rtt), total+rtt
		e.Printf("64 bytes from %s: seq=%d ttl=%d time=%.3f ms\n", ip, sent, 50+len(host)%10, rtt)
		sent++
	}
	e.Printf("\n--- %s ping statistics ---\n%d packets transmitted, %d packets received, 0%% packet loss\n", host, sent, sent)
	if sent > 0 {
		e.Printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n", minRTT, total/float64(sent), maxRTT)
	}
	return 0
}

const ifconfigText = `eth0      Link encap:Ethernet  HWaddr 00:12:41:5A:7C:E4
          inet addr:192.168.1.108  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3018473 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5523128 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:412859221 (393.7 MiB)  TX bytes:3921884105 (3.6 GiB)
          Interrupt:43

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:1834 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1834 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:146720 (143.2 KiB)  TX bytes:146720 (143.2 KiB)

`

func cmdIfconfig(e *shell.Env) int {
	o := e.Flags()
	if len(o.Args) > 1 { // configuring an interface
		if !e.User().IsRoot() {
			e.Errorf("SIOCSIFADDR: Permission denied")
			return 1
		}
		return 0
	}
	if len(o.Args) == 1 && o.Args[0] != "eth0" && o.Args[0] != "lo" {
		e.Errorf("%s: error fetching interface information: Device not found", o.Args[0])
		return 1
	}
	e.Print(ifconfigText)
	return 0
}

func cmdNetstat(e *shell.Env) int {
	o := e.Flags()
	all := o.Has("a")
	switch {
	case all:
		e.Print("Active Internet connections (servers and established)\n")
	case o.Has("l"):
		e.Print("Active Internet connections (only servers)\n")
	default:
		e.Print("Active Internet connections (w/o servers)\n")
	}
	header := "Proto Recv-Q Send-Q Local Address           Foreign Address         State       "
	if o.Has("p") {
		header += "PID/Program name"
	}
	e.Printf("%s\n", header)
	row := func(proto, local, foreign, state, prog string) {
		line := fmt.Sprintf("%-5s %6d %6d %-23s %-23s %-11s ", proto, 0, 0, local, foreign, state)
		if o.Has("p") {
			line += prog
		}
		e.Printf("%s\n", line)
	}
	if all || o.Has("l") {
		row("tcp", "0.0.0.0:80", "0.0.0.0:*", "LISTEN", "612/ipcam")
		row("tcp", "0.0.0.0:554", "0.0.0.0:*", "LISTEN", "612/ipcam")
		row("tcp", "0.0.0.0:34567", "0.0.0.0:*", "LISTEN", "612/ipcam")
		row("tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN", "731/dropbear")
	}
	if !o.Has("l") {
		row("tcp", "192.168.1.108:22", fmt.Sprintf("%s:%d", e.Session().ClientIP, 40000+e.Session().PID%20000), "ESTABLISHED", fmt.Sprintf("%d/dropbear", e.Session().PID-1))
	}
	if all || o.Has("l") {
		row("udp", "0.0.0.0:3702", "0.0.0.0:*", "", "612/ipcam")
	}
	return 0
}

func cmdRoute(e *shell.Env) int {
	if len(e.Args) > 1 && e.Args[1] != "-n" && e.Args[1] != "-e" {
		if !e.User().IsRoot() {
			e.Errorf("SIOCADDRT: Operation not permitted")
			return 1
		}
		return 0 // add/del as root
	}
	e.Print(`Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG    0      0        0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0
`)
	return 0
}

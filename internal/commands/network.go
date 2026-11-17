package commands

import (
	"fmt"
	"time"

	"github.com/antonmedv/ssham/internal/rootfs"
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
	count, deadline := -1, -1
	if c, ok := o.Value("c"); ok {
		fmt.Sscan(c, &count)
	}
	if w, ok := o.Value("w"); ok {
		fmt.Sscan(w, &deadline)
	}
	ip, kind, ok := resolve(e, host)
	if !ok {
		e.Errorf("bad address '%s'", host)
		return 1
	}
	// Only the camera and the router answer; see net.go.
	var base float64
	switch kind {
	case hostSelf:
		base = 0.04
	case hostGateway:
		base = 0.45
	}
	e.Printf("PING %s (%s): 56 data bytes\n", host, ip)
	sent, received := 0, 0
	minRTT, maxRTT, total := 1e9, 0.0, 0.0
	for (count < 0 || sent < count) && (deadline < 0 || sent < deadline) {
		if sent > 0 && !e.Sleep(time.Second) {
			break
		}
		if base > 0 {
			rtt := base + e.Rand().Float64()*base*1.5
			minRTT, maxRTT, total = min(minRTT, rtt), max(maxRTT, rtt), total+rtt
			e.Printf("64 bytes from %s: seq=%d ttl=64 time=%.3f ms\n", ip, sent, rtt)
			received++
		}
		sent++
	}
	if received == 0 && count > 0 && deadline < 0 {
		e.Sleep(10 * time.Second) // -W 10: how long ping waits for a reply
	}
	e.Printf("\n--- %s ping statistics ---\n%d packets transmitted, %d packets received, %d%% packet loss\n",
		host, sent, received, (sent-received)*100/max(sent, 1))
	if received > 0 {
		e.Printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n", minRTT, total/float64(received), maxRTT)
		return 0
	}
	return 1
}

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
	h := e.Host()
	stats := rootfs.NetDev(e.Now().Sub(h.Booted))
	show := func(name string) bool { return len(o.Args) == 0 || o.Args[0] == name }
	if show("eth0") {
		i := stats[0]
		e.Printf("eth0      Link encap:Ethernet  HWaddr %s\n", h.MAC)
		e.Printf("          inet addr:%s  Bcast:192.168.1.255  Mask:255.255.255.0\n", h.IP)
		e.Print("          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n")
		e.Printf("          RX packets:%d errors:0 dropped:0 overruns:0 frame:0\n", i.RxPkts)
		e.Printf("          TX packets:%d errors:0 dropped:0 overruns:0 carrier:0\n", i.TxPkts)
		e.Print("          collisions:0 txqueuelen:1000\n")
		e.Printf("          RX bytes:%d (%s)  TX bytes:%d (%s)\n", i.RxBytes, scaledBytes(i.RxBytes), i.TxBytes, scaledBytes(i.TxBytes))
		e.Print("          Interrupt:43\n\n")
	}
	if show("lo") {
		i := stats[1]
		e.Print("lo        Link encap:Local Loopback\n")
		e.Print("          inet addr:127.0.0.1  Mask:255.0.0.0\n")
		e.Print("          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n")
		e.Printf("          RX packets:%d errors:0 dropped:0 overruns:0 frame:0\n", i.RxPkts)
		e.Printf("          TX packets:%d errors:0 dropped:0 overruns:0 carrier:0\n", i.TxPkts)
		e.Print("          collisions:0 txqueuelen:1000\n")
		e.Printf("          RX bytes:%d (%s)  TX bytes:%d (%s)\n\n", i.RxBytes, scaledBytes(i.RxBytes), i.TxBytes, scaledBytes(i.TxBytes))
	}
	return 0
}

// scaledBytes is how BusyBox ifconfig shows a byte count: 393.7 MiB.
func scaledBytes(n uint32) string {
	v := float64(n)
	unit := "B"
	for _, u := range []string{"KiB", "MiB", "GiB"} {
		if v < 1024 {
			break
		}
		v /= 1024
		unit = u
	}
	if unit == "B" {
		return fmt.Sprintf("%d.0 B", n)
	}
	return fmt.Sprintf("%.1f %s", v, unit)
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
		row("tcp", "0.0.0.0:80", "0.0.0.0:*", "LISTEN", "126/ipcam")
		row("tcp", "0.0.0.0:554", "0.0.0.0:*", "LISTEN", "126/ipcam")
		row("tcp", "0.0.0.0:34567", "0.0.0.0:*", "LISTEN", "126/ipcam")
		row("tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN", "124/dropbear")
	}
	if !o.Has("l") {
		row("tcp", e.Host().IP+":22", fmt.Sprintf("%s:%d", e.Session().ClientIP, e.Session().ClientPort), "ESTABLISHED", fmt.Sprintf("%d/dropbear", e.Session().PID-1))
	}
	if all || o.Has("l") {
		row("udp", "0.0.0.0:3702", "0.0.0.0:*", "", "126/ipcam")
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

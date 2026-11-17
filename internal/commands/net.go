package commands

import (
	"net"
	"strings"
	"time"

	"github.com/antonmedv/ssham/internal/shell"
)

// The camera's network. It sits on a home LAN (192.168.1.0/24, the router
// at .1, the camera at Host.IP), but whoever installed it blocked its internet access, as is
// common for cameras. So DNS never answers and outside addresses never
// reply, while the camera itself and the router do. This is consistent
// from every angle, unlike faking replies: an attacker who points wget at
// their own server would see that no request ever arrives.
//
// Nothing here touches the real network.

const gatewayIP = "192.168.1.1"

type hostKind int

const (
	hostSelf    hostKind = iota // the camera: 127.0.0.0/8 and its LAN address
	hostGateway                 // the home router
	hostLAN                     // another LAN address: nothing answers ARP
	hostOutside                 // the internet: blocked
)

// Timeouts, as a 4.9 kernel and BusyBox's resolver produce them.
const (
	dnsTimeout     = 10 * time.Second  // 2 nameservers x 5s
	connectTimeout = 127 * time.Second // tcp_syn_retries = 6
	arpTimeout     = 3 * time.Second   // then EHOSTUNREACH
)

// resolve looks host up in /etc/hosts. Any other name needs DNS, which
// waits for the timeout and fails: ok is false and the caller prints
// "bad address". It returns false at once if interrupted.
func resolve(e *shell.Env, host string) (ip string, kind hostKind, ok bool) {
	if a := net.ParseIP(host); a != nil && a.To4() != nil {
		return host, kindOf(a.To4(), e.Host().IP), true
	}
	hosts, _ := e.FS.AsRoot().ReadFile("/etc/hosts")
	for _, l := range splitLines(string(hosts)) {
		f := strings.Fields(l)
		for _, name := range f[min(1, len(f)):] {
			if name == host {
				return resolve(e, f[0])
			}
		}
	}
	e.Sleep(dnsTimeout)
	return "", 0, false
}

func kindOf(ip net.IP, self string) hostKind {
	switch {
	case ip[0] == 127, ip.String() == self:
		return hostSelf
	case ip.String() == gatewayIP:
		return hostGateway
	case ip[0] == 192 && ip[1] == 168 && ip[2] == 1:
		return hostLAN
	}
	return hostOutside
}

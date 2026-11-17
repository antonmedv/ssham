package rootfs

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Identify fills in what makes this camera different from every other
// ssham: its address, MAC and the Wi-Fi it knows. They are derived from
// seed (the host key), so they stay the same across restarts of one
// deployment, and a scanner cannot recognise ssham by a fixed MAC or
// password.
func (h *Host) Identify(seed []byte) {
	sum := sha256.Sum256(append([]byte("ssham identity"), seed...))
	n := func(i int) uint32 { return binary.BigEndian.Uint32(sum[i*4:]) }
	if h.IP == "" {
		h.IP = fmt.Sprintf("192.168.1.%d", 100+n(0)%100)
	}
	if h.MAC == "" {
		// 00:12:41 is a common OUI on cheap cameras' Ethernet chips.
		h.MAC = fmt.Sprintf("00:12:41:%02X:%02X:%02X", sum[4], sum[5], sum[6])
	}
	if h.WifiSSID == "" {
		ssids := []string{"HomeNet-5G", "TP-Link_%04X", "NETGEAR%02d", "Linksys%05d", "FRITZ!Box 7530 %s", "Vodafone-%04X", "dlink-%04X", "ASUS_%02X_2G"}
		f := ssids[n(2)%uint32(len(ssids))]
		switch f {
		case "HomeNet-5G":
			h.WifiSSID = f
		case "FRITZ!Box 7530 %s":
			h.WifiSSID = fmt.Sprintf(f, []string{"XL", "WF", "VB"}[n(3)%3])
		default:
			h.WifiSSID = fmt.Sprintf(f, n(3)%65536%100000)
		}
	}
	if h.WifiPSK == "" {
		words := []string{"sunflower", "dragon", "monkey", "princess", "family", "summer", "welcome", "shadow", "football", "sweethome"}
		h.WifiPSK = fmt.Sprintf("%s%d", words[n(4)%uint32(len(words))], 1990+n(5)%35)
	}
}

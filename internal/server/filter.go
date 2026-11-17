package server

import (
	"io"
	"regexp"
)

// fingerprintSeqs matches escape sequences Bubble Tea emits that bash never
// would: keyboard protocol negotiation (modifyOtherKeys, kitty), terminal
// mode queries (DECRQM), and cursor shape changes (DECSCUSR). A curious
// attacker could spot these with `script` or a hex dump, so they are dropped.
// Without them the terminal stays in legacy key mode, which Bubble Tea's
// input decoder handles fine.
var fingerprintSeqs = regexp.MustCompile(
	`\x1b\[>4(;\d+)?m` + // modifyOtherKeys set/reset
		`|\x1b\[[>=<]\d*(;\d+)?u` + // kitty keyboard push/set/pop
		`|\x1b\[\?u` + // kitty keyboard query
		`|\x1b\[\?\d+\$p` + // DECRQM mode query
		`|\x1b\[\?(2026|2027)[hl]` + // synchronized output / unicode core
		`|\x1b\[\d* q`, // cursor shape
)

// filterWriter strips fingerprintSeqs from everything written to w. The
// renderer writes whole frames per call, so sequences are not split across
// writes in practice.
type filterWriter struct{ w io.Writer }

func (f filterWriter) Write(p []byte) (int, error) {
	out := fingerprintSeqs.ReplaceAll(p, nil)
	if len(out) == 0 {
		return len(p), nil
	}
	if _, err := f.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

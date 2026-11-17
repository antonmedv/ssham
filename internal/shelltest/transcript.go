package shelltest

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite transcript files with the actual output")

// RunTranscripts runs every transcript file matching pattern as a subtest.
//
// A transcript looks like a terminal session:
//
//	// A comment.
//	@user admin
//	$ sudo whoami
//	< hunter2
//	[sudo] password for admin:
//	root
//	$ ls /nope
//	ls: cannot access '/nope': No such file or directory
//	[exit 2]
//
// Lines are:
//
//	$ cmd     run cmd at the prompt
//	< text    a line typed at the next prompt (passwords, read, ...)
//	@user u   start a fresh session as u (each file starts as root)
//	// text   a comment
//
// Everything else is the expected output of the command above it. A
// non-zero exit status shows as [exit N]. Output without a final newline
// ends with [no newline]. Escape characters show as ^[.
//
// Run `go test -update` to rewrite the files with the actual output; review
// the diff with git.
func RunTranscripts(t *testing.T, pattern string) {
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		t.Fatalf("no transcripts match %s", pattern)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), filepath.Ext(file)), func(t *testing.T) {
			runTranscript(t, file)
		})
	}
}

type step struct {
	header []string // comments and @user lines before the command
	cmd    string
	input  []string
	want   []string
	line   int
}

func parse(data string) []step {
	var steps []step
	var cur *step
	var header []string
	for i, line := range strings.Split(strings.TrimRight(data, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "$ "):
			steps = append(steps, step{header: header, cmd: line[2:], line: i + 1})
			cur = &steps[len(steps)-1]
			header = nil
		case cur != nil && len(cur.want) == 0 && strings.HasPrefix(line, "< "):
			cur.input = append(cur.input, line[2:])
		case strings.HasPrefix(line, "@") || strings.HasPrefix(line, "//") || cur == nil:
			header = append(header, line)
			cur = nil
		default:
			cur.want = append(cur.want, line)
		}
	}
	if len(header) > 0 {
		steps = append(steps, step{header: header})
	}
	return steps
}

func runTranscript(t *testing.T, file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	steps := parse(string(data))
	sess := New(t, "root")
	var out strings.Builder
	failed := false
	for _, st := range steps {
		for _, h := range st.header {
			out.WriteString(h + "\n")
			if user, ok := strings.CutPrefix(h, "@user "); ok {
				sess = New(t, strings.TrimSpace(user))
			}
		}
		if st.cmd == "" {
			continue
		}
		got := format(sess.Run(st.cmd, st.input...))
		out.WriteString("$ " + st.cmd + "\n")
		for _, in := range st.input {
			out.WriteString("< " + in + "\n")
		}
		out.WriteString(got)
		// Keep blank lines that separate sections, beyond any the output
		// itself ends with.
		for range trailingBlank(st.want) - trailingBlank(strings.Split(strings.TrimSuffix(got, "\n"), "\n")) {
			out.WriteString("\n")
		}
		if want := normalize(strings.Join(st.want, "\n")); want != normalize(got) && !*update {
			failed = true
			t.Errorf("%s:%d: $ %s\n--- want ---\n%s\n--- got ---\n%s", file, st.line, st.cmd, want, normalize(got))
		}
	}
	if *update {
		if err := os.WriteFile(file, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	} else if failed {
		t.Log("run `go test -update` to accept the new output, then review the diff")
	}
}

// format renders a command's output the way it is stored in a transcript.
func format(output string, status int) string {
	s := clean(output)
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n[no newline]\n"
	}
	if status != 0 {
		s += fmt.Sprintf("[exit %d]\n", status)
	}
	return s
}

// normalize ignores trailing spaces and trailing blank lines, which editors
// tend to strip.
func normalize(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// trailingBlank counts the empty lines at the end of lines.
func trailingBlank(lines []string) int {
	n := 0
	for i := len(lines) - 1; i >= 0 && strings.TrimSpace(lines[i]) == ""; i-- {
		n++
	}
	return n
}

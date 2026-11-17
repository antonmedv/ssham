// Package rootfs builds the fake Ubuntu disk that every session starts from.
//
// The disk lives in files/ as ordinary files, so adding a bait file is just
// a matter of dropping it into the right folder. Files ending in .tmpl are
// rendered with text/template using Host (e.g. {{.Hostname}}). Everything is
// owned by root:root with mode 0644 (files) or 0755 (directories) unless
// listed in modes below.
package rootfs

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"text/template"
	"time"

	"github.com/antonmedv/ssham/internal/vfs"
)

//go:embed all:files
var files embed.FS

// Host describes the machine the honeypot pretends to be.
type Host struct {
	Hostname string
	Kernel   string // e.g. "6.8.0-48-generic"
	Booted   time.Time
}

type attr struct {
	mode  fs.FileMode
	owner string
}

// modes lists paths whose permissions or owner differ from the defaults.
var modes = map[string]attr{
	"/dev/null":                              {0o666, "root"},
	"/dev/random":                            {0o666, "root"},
	"/dev/sda":                               {0o660, "root"},
	"/dev/sda1":                              {0o660, "root"},
	"/dev/sda15":                             {0o660, "root"},
	"/dev/sda2":                              {0o660, "root"},
	"/dev/shm":                               {0o1777, "root"},
	"/dev/tty":                               {0o666, "root"},
	"/dev/urandom":                           {0o666, "root"},
	"/dev/zero":                              {0o666, "root"},
	"/etc/gshadow":                           {0o640, "root"},
	"/etc/shadow":                            {0o640, "root"},
	"/etc/ssh/ssh_host_ed25519_key":          {0o600, "root"},
	"/etc/sudoers":                           {0o440, "root"},
	"/home/ubuntu":                           {0o750, "ubuntu"},
	"/home/ubuntu/.bashrc":                   {0o644, "ubuntu"},
	"/home/ubuntu/.profile":                  {0o644, "ubuntu"},
	"/proc/cpuinfo":                          {0o444, "root"},
	"/proc/loadavg":                          {0o444, "root"},
	"/proc/meminfo":                          {0o444, "root"},
	"/proc/mounts":                           {0o444, "root"},
	"/proc/self/status":                      {0o444, "root"},
	"/proc/version":                          {0o444, "root"},
	"/root":                                  {0o700, "root"},
	"/root/.bash_history":                    {0o600, "root"},
	"/root/.ssh":                             {0o700, "root"},
	"/root/.ssh/authorized_keys":             {0o600, "root"},
	"/tmp":                                   {0o1777, "root"},
	"/var/backups/db_dump_2024-10-01.sql.gz": {0o640, "root"},
	"/var/log":                               {0o775, "root"},
	"/var/log/auth.log":                      {0o640, "root"},
	"/var/log/lastlog":                       {0o664, "root"},
	"/var/log/syslog":                        {0o640, "root"},
	"/var/spool/cron/crontabs":               {0o730, "root"},
	"/var/tmp":                               {0o1777, "root"},
	"/var/www/html":                          {0o755, "www-data"},
	"/var/www/html/config.php":               {0o640, "www-data"},
	"/var/www/html/index.html":               {0o644, "www-data"},
}

// links lists symbolic links, as path: target.
var links = map[string]string{
	"/bin":                "usr/bin",
	"/lib":                "usr/lib",
	"/lib64":              "usr/lib64",
	"/sbin":               "usr/sbin",
	"/usr/lib/os-release": "../../etc/os-release",
}

// dirs lists empty directories (git and embed cannot hold those).
var dirs = []string{
	"/boot", "/dev/shm", "/etc/cron.d", "/etc/cron.daily", "/etc/systemd",
	"/media", "/mnt", "/opt", "/run", "/snap", "/srv", "/sys", "/tmp",
	"/usr/bin", "/usr/local/bin", "/usr/sbin", "/usr/share", "/var/cache",
	"/var/lib", "/var/mail", "/var/spool/cron/crontabs", "/var/tmp",
}

// Build returns a fresh filesystem for host. Sessions should Clone it.
func Build(h Host) (*vfs.FS, error) {
	f := vfs.New()
	mtime := h.Booted.Add(-90 * 24 * time.Hour).Truncate(time.Minute)
	if root, err := f.Lstat("root", "/"); err == nil {
		root.ModTime = mtime
	}

	node := func(p string, mode fs.FileMode, data []byte) *vfs.Node {
		a, ok := modes[p]
		if !ok {
			a = attr{mode: mode, owner: "root"}
		}
		n := &vfs.Node{Mode: a.mode, Owner: a.owner, Group: a.owner, ModTime: mtime, Data: data}
		if mode&fs.ModeDir != 0 {
			n.Mode |= fs.ModeDir
		}
		return n
	}

	err := fs.WalkDir(files, "files", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "files" {
			return err
		}
		p := strings.TrimPrefix(name, "files")
		if d.IsDir() {
			f.Put(p, node(p, fs.ModeDir|0o755, nil))
			return nil
		}
		data, err := files.ReadFile(name)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".tmpl") {
			p = strings.TrimSuffix(p, ".tmpl")
			if data, err = render(name, data, h); err != nil {
				return err
			}
		}
		f.Put(p, node(p, 0o644, data))
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range dirs {
		f.Put(p, node(p, fs.ModeDir|0o755, nil))
	}
	for p, target := range links {
		f.Put(p, &vfs.Node{Mode: fs.ModeSymlink | 0o777, Owner: "root", Group: "root", ModTime: mtime, Target: target})
	}
	return f, nil
}

func render(name string, data []byte, h Host) ([]byte, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("rootfs: %s: %w", name, err)
	}
	var b bytes.Buffer
	if err := t.Execute(&b, h); err != nil {
		return nil, fmt.Errorf("rootfs: %s: %w", name, err)
	}
	return b.Bytes(), nil
}

// AddUser makes sure user has a home directory and entries in /etc/passwd,
// /etc/group and /etc/shadow, so `id`, `ls -l` and `cd ~` all agree. It
// returns the home directory. Existing users are left alone.
func AddUser(f *vfs.FS, user string, uid int) string {
	if user == "root" {
		return "/root"
	}
	home := "/home/" + user
	passwd, _ := f.ReadFile("root", "/etc/passwd")
	if bytes.Contains(append([]byte("\n"), passwd...), []byte("\n"+user+":")) {
		return home
	}
	mtime := f.Now().Add(-37 * 24 * time.Hour).Truncate(time.Minute)
	put := func(p string, mode fs.FileMode, data string) {
		f.Put(p, &vfs.Node{Mode: mode, Owner: user, Group: user, ModTime: mtime, Data: []byte(data)})
	}
	bashrc, _ := f.ReadFile("root", "/home/ubuntu/.bashrc")
	put(home, fs.ModeDir|0o750, "")
	put(home+"/.bashrc", 0o644, string(bashrc))
	put(home+"/.profile", 0o644, "# ~/.profile\n")
	put(home+"/.bash_logout", 0o644, "# ~/.bash_logout: executed by bash(1) when login shell exits.\n")

	_ = f.WriteFile("root", "/etc/passwd", fmt.Appendf(nil, "%s:x:%d:%d:%s:%s:/bin/bash\n", user, uid, uid, user, home), true)
	_ = f.WriteFile("root", "/etc/shadow", fmt.Appendf(nil, "%s:$y$j9T$Q2m0yH5p.d1kQxR3b9uV0/$J7m0tq1oVwVn8Q7P1nB2xjQ8r9q9YkF7aZb0H2kLw3.:19997:0:99999:7:::\n", user), true)

	// Own group, and membership in sudo so that `sudo` looks plausible.
	group, _ := f.ReadFile("root", "/etc/group")
	lines := strings.Split(strings.TrimSuffix(string(group), "\n"), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "sudo:") {
			if !strings.HasSuffix(l, ":") {
				l += ","
			}
			lines[i] = l + user
		}
	}
	lines = append(lines, fmt.Sprintf("%s:x:%d:", user, uid))
	_ = f.WriteFile("root", "/etc/group", []byte(strings.Join(lines, "\n")+"\n"), false)
	return home
}

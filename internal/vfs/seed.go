package vfs

import (
	"fmt"
	"io/fs"
	"strings"
	"time"
)

// Host describes the machine the honeypot pretends to be.
type Host struct {
	Hostname string
	Kernel   string // e.g. "6.8.0-48-generic"
	Booted   time.Time
}

// Binaries is the set of commands that appear to be installed, by directory.
// The shell uses this for `which`, `type`, and PATH lookups.
var Binaries = map[string][]string{
	"/usr/bin": {
		"apt", "apt-get", "awk", "base64", "basename", "bash", "cat", "chattr", "chmod", "chown",
		"clear", "cp", "crontab", "curl", "cut", "date", "dd", "df", "diff", "dirname", "dmesg",
		"du", "echo", "env", "false", "file", "find", "free", "gawk", "grep", "groups", "gzip",
		"head", "hostname", "hostnamectl", "id", "ip", "kill", "last", "less", "ln", "ls", "lsb_release", "lscpu",
		"lsblk", "md5sum", "mkdir", "more", "mv", "nano", "netstat", "nohup", "nproc", "passwd",
		"perl", "ping", "printf", "ps", "pwd", "python3", "readlink", "rm", "rmdir", "scp", "sed",
		"seq", "sh", "sha256sum", "sleep", "sort", "ss", "ssh", "stat", "su", "sudo", "systemctl",
		"tail", "tar", "tee", "top", "touch", "tr", "true", "uname", "uniq", "uptime", "vi", "vim",
		"w", "wc", "wget", "whereis", "which", "who", "whoami", "xargs", "yes",
	},
	"/usr/sbin": {"chpasswd", "ifconfig", "iptables", "reboot", "service", "shutdown", "sshd", "useradd", "usermod"},
}

// NewBase builds the shared template filesystem. Sessions should Clone it.
func NewBase(h Host) *FS {
	f := New()
	mt := h.Booted.Add(-90 * 24 * time.Hour).Truncate(time.Minute)
	f.root.ModTime = mt

	dir := func(p string, mode fs.FileMode, owner string) {
		f.Put(p, &Node{Mode: fs.ModeDir | mode, Owner: owner, Group: owner, ModTime: mt})
	}
	file := func(p string, mode fs.FileMode, owner, content string) {
		f.Put(p, &Node{Mode: mode, Owner: owner, Group: owner, ModTime: mt, Data: []byte(content)})
	}
	link := func(p, target string) {
		f.Put(p, &Node{Mode: fs.ModeSymlink | 0o777, Owner: "root", Group: "root", ModTime: mt, Target: target})
	}

	for _, d := range []string{"/boot", "/dev", "/etc", "/home", "/media", "/mnt", "/opt", "/proc", "/run", "/srv", "/sys", "/usr", "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/share", "/var", "/var/lib", "/var/cache", "/var/backups", "/var/mail", "/snap", "/etc/cron.d", "/etc/cron.daily", "/etc/ssh", "/etc/apt", "/etc/systemd", "/var/spool", "/var/spool/cron"} {
		dir(d, 0o755, "root")
	}
	dir("/root", 0o700, "root")
	dir("/tmp", 0o1777, "root")
	dir("/var/tmp", 0o1777, "root")
	dir("/dev/shm", 0o1777, "root")
	dir("/var/log", 0o775, "root")
	dir("/var/www", 0o755, "root")
	dir("/var/www/html", 0o755, "www-data")
	dir("/var/spool/cron/crontabs", 0o730, "root")
	link("/bin", "usr/bin")
	link("/sbin", "usr/sbin")
	link("/lib", "usr/lib")
	link("/lib64", "usr/lib64")

	for d, names := range Binaries {
		for i, name := range names {
			size := int64(35000 + (i*7919)%140000)
			f.Put(d+"/"+name, &Node{Mode: 0o755, Owner: "root", Group: "root", ModTime: mt,
				Data: []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00"), FakeSize: size})
		}
	}
	link("/usr/bin/python", "python3")
	f.Put("/usr/bin/sudo", &Node{Mode: 0o4755, Owner: "root", Group: "root", ModTime: mt, Data: []byte("\x7fELF\x02\x01\x01"), FakeSize: 277936})
	f.Put("/usr/bin/passwd", &Node{Mode: 0o4755, Owner: "root", Group: "root", ModTime: mt, Data: []byte("\x7fELF\x02\x01\x01"), FakeSize: 64152})

	file("/dev/null", 0o666, "root", "")
	file("/dev/zero", 0o666, "root", "")
	file("/dev/random", 0o666, "root", "")
	file("/dev/urandom", 0o666, "root", "")
	file("/dev/tty", 0o666, "root", "")
	for _, d := range []string{"/dev/sda", "/dev/sda1", "/dev/sda2", "/dev/sda15"} {
		file(d, 0o660, "root", "")
	}

	file("/etc/hostname", 0o644, "root", h.Hostname+"\n")
	file("/etc/hosts", 0o644, "root", fmt.Sprintf("127.0.0.1 localhost\n127.0.1.1 %s\n\n# The following lines are desirable for IPv6 capable hosts\n::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n10.0.2.21 db01.internal db01\n", h.Hostname))
	file("/etc/os-release", 0o644, "root", osRelease)
	link("/usr/lib/os-release", "../../etc/os-release")
	file("/etc/lsb-release", 0o644, "root", "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=24.04\nDISTRIB_CODENAME=noble\nDISTRIB_DESCRIPTION=\"Ubuntu 24.04.1 LTS\"\n")
	file("/etc/issue", 0o644, "root", "Ubuntu 24.04.1 LTS \\n \\l\n\n")
	file("/etc/issue.net", 0o644, "root", "Ubuntu 24.04.1 LTS\n")
	file("/etc/debian_version", 0o644, "root", "trixie/sid\n")
	file("/etc/timezone", 0o644, "root", "Etc/UTC\n")
	file("/etc/shells", 0o644, "root", "# /etc/shells: valid login shells\n/bin/sh\n/usr/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/rbash\n/usr/bin/rbash\n/bin/dash\n/usr/bin/dash\n")
	file("/etc/resolv.conf", 0o644, "root", "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n# Do not edit.\n\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n")
	file("/etc/passwd", 0o644, "root", passwd)
	file("/etc/group", 0o644, "root", group)
	file("/etc/shadow", 0o640, "root", shadow)
	file("/etc/gshadow", 0o640, "root", "root:*::\nsudo:*::ubuntu\n")
	file("/etc/sudoers", 0o440, "root", "Defaults\tenv_reset\nDefaults\tmail_badpass\nDefaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"\nDefaults\tuse_pty\n\nroot\tALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n%sudo\tALL=(ALL:ALL) ALL\n\n@includedir /etc/sudoers.d\n")
	file("/etc/fstab", 0o644, "root", "LABEL=cloudimg-rootfs\t/\t ext4\tdiscard,commit=30,errors=remount-ro\t0 1\nLABEL=UEFI\t/boot/efi\tvfat\tumask=0077\t0 1\n")
	file("/etc/crontab", 0o644, "root", crontab)
	file("/etc/motd", 0o644, "root", "")
	file("/etc/environment", 0o644, "root", "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\"\n")
	file("/etc/ssh/sshd_config", 0o644, "root", sshdConfig)
	file("/etc/ssh/ssh_host_ed25519_key.pub", 0o644, "root", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0b7Rr8p1Kc0bq8yE7r5tWl0m3Vq9zQ4x2Kp1f6NnB root@"+h.Hostname+"\n")
	file("/etc/ssh/ssh_host_ed25519_key", 0o600, "root", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n")
	file("/etc/apt/sources.list", 0o644, "root", "# Ubuntu sources have moved to /etc/apt/sources.list.d/ubuntu.sources\n")

	file("/proc/cpuinfo", 0o444, "root", cpuinfo(4))
	file("/proc/meminfo", 0o444, "root", meminfo)
	file("/proc/version", 0o444, "root", fmt.Sprintf("Linux version %s (buildd@lcy02-amd64-075) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #48-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 27 14:04:52 UTC 2024\n", h.Kernel))
	file("/proc/loadavg", 0o444, "root", "0.08 0.03 0.01 1/187 31337\n")
	file("/proc/mounts", 0o444, "root", "/dev/sda1 / ext4 rw,relatime,discard,errors=remount-ro,commit=30 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=400460k,mode=755 0 0\n/dev/sda15 /boot/efi vfat rw,relatime,fmask=0077,dmask=0077 0 0\n")
	file("/proc/self/status", 0o444, "root", "Name:\tbash\nState:\tS (sleeping)\nPid:\t31337\nPPid:\t31336\n")

	file("/var/log/auth.log", 0o640, "root", "")
	file("/var/log/syslog", 0o640, "root", "")
	file("/var/log/dpkg.log", 0o644, "root", "2024-10-02 06:12:01 startup archives unpack\n2024-10-02 06:12:03 upgrade openssl:amd64 3.0.13-0ubuntu3.3 3.0.13-0ubuntu3.4\n")
	file("/var/log/lastlog", 0o664, "root", "")

	file("/var/www/html/index.html", 0o644, "www-data", "<!DOCTYPE html>\n<html><head><title>Welcome to nginx!</title></head>\n<body><h1>Welcome to nginx!</h1></body></html>\n")
	// Bait: a config file with honeytoken credentials.
	file("/var/www/html/config.php", 0o640, "www-data", "<?php\ndefine('DB_HOST', '10.0.2.21');\ndefine('DB_NAME', 'shop_prod');\ndefine('DB_USER', 'shop');\ndefine('DB_PASSWORD', 'Wint3r!2024#shop');\n")
	file("/var/backups/db_dump_2024-10-01.sql.gz", 0o640, "root", "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03")

	file("/root/.bashrc", 0o644, "root", bashrc)
	file("/root/.profile", 0o644, "root", "# ~/.profile: executed by Bourne-compatible login shells.\n\nif [ \"$BASH\" ]; then\n  if [ -f ~/.bashrc ]; then\n    . ~/.bashrc\n  fi\nfi\n\nmesg n 2> /dev/null || true\n")
	file("/root/.bash_history", 0o600, "root", "apt update\napt upgrade -y\nsystemctl restart nginx\nmysql -h db01.internal -u shop -p\ncd /var/www/html\nvim config.php\nexit\n")
	dir("/root/.ssh", 0o700, "root")
	file("/root/.ssh/authorized_keys", 0o600, "root", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB4m2Wq1oN7Zt8u3sQyFvK0bXlR9cP2hJdE6aGf5UiTr deploy@ci\n")

	dir("/home/ubuntu", 0o750, "ubuntu")
	file("/home/ubuntu/.bashrc", 0o644, "ubuntu", bashrc)
	file("/home/ubuntu/.profile", 0o644, "ubuntu", "# ~/.profile\nif [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n")
	return f
}

// AddUser makes sure the session's user has a home directory and appears in
// /etc/passwd, so that `id`, `ls -l` and `cd ~` all look consistent.
func AddUser(f *FS, user string, uid int) string {
	home := "/home/" + user
	if user == "root" {
		return "/root"
	}
	if user == "ubuntu" {
		return home
	}
	mt := f.Now().Add(-37 * 24 * time.Hour).Truncate(time.Minute)
	f.Put(home, &Node{Mode: fs.ModeDir | 0o750, Owner: user, Group: user, ModTime: mt})
	f.Put(home+"/.bashrc", &Node{Mode: 0o644, Owner: user, Group: user, ModTime: mt, Data: []byte(bashrc)})
	f.Put(home+"/.profile", &Node{Mode: 0o644, Owner: user, Group: user, ModTime: mt, Data: []byte("# ~/.profile\n")})
	f.Put(home+"/.bash_logout", &Node{Mode: 0o644, Owner: user, Group: user, ModTime: mt, Data: []byte("# ~/.bash_logout: executed by bash(1) when login shell exits.\n")})

	appendLine := func(p, line string) {
		n, err := f.Stat("", p)
		if err != nil || strings.Contains(string(n.Data), "\n"+strings.SplitN(line, ":", 2)[0]+":") {
			return
		}
		n.Data = append(n.Data, []byte(line+"\n")...)
	}
	appendLine("/etc/passwd", fmt.Sprintf("%s:x:%d:%d:%s:%s:/bin/bash", user, uid, uid, user, home))
	appendLine("/etc/group", fmt.Sprintf("%s:x:%d:", user, uid))
	appendLine("/etc/shadow", fmt.Sprintf("%s:$y$j9T$Q2m0yH5p.d1kQxR3b9uV0/$J7m0tq1oVwVn8Q7P1nB2xjQ8r9q9YkF7aZb0H2kLw3.:19997:0:99999:7:::", user))
	return home
}

func cpuinfo(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `processor	: %d
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
stepping	: 7
microcode	: 0x5003707
cpu MHz		: 2499.998
cache size	: 36608 KB
physical id	: 0
siblings	: %d
core id		: %d
cpu cores	: %d
apicid		: %d
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke
bogomips	: 4999.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:

`, i, n, i, n, i*2)
	}
	return b.String()
}

const osRelease = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
`

const passwd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
`

const group = `root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:
disk:x:6:
www-data:x:33:
sudo:x:27:ubuntu
users:x:100:
nogroup:x:65534:
mysql:x:113:
ubuntu:x:1000:
`

const shadow = `root:$y$j9T$PqK2sNw9bLx3T1nYb.0vC/$7uQ8yZq3K1mWvR0xFh2nP9dJt6bE4cA5sL8gU1oI2kD:19997:0:99999:7:::
daemon:*:19997:0:99999:7:::
bin:*:19997:0:99999:7:::
sys:*:19997:0:99999:7:::
www-data:*:19997:0:99999:7:::
nobody:*:19997:0:99999:7:::
sshd:*:19997:0:99999:7:::
mysql:!:19997:0:99999:7:::
ubuntu:$y$j9T$1sF7wLq0Rk2Zp9vN4bXcA/$Hk3mT8yQ2vW1nB7cR5dF0gJ4pL6sZ9xU3aE8oI1qM2K:19997:0:99999:7:::
`

const crontab = `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6	1 * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
30 2	* * *	root	/usr/local/bin/backup.sh > /dev/null 2>&1
`

const meminfo = `MemTotal:        4005504 kB
MemFree:          212644 kB
MemAvailable:    2871236 kB
Buffers:          118400 kB
Cached:          2493120 kB
SwapCached:            0 kB
Active:          1290536 kB
Inactive:        2096348 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:               188 kB
Shmem:              1104 kB
`

const sshdConfig = `Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0

PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
`

const bashrc = `# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s checkwinsize

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi

alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
`

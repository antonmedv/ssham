package shell

// commands maps program names to their simulations. A command only runs if
// its binary is present on $PATH in the session's virtual filesystem, so an
// attacker who deletes /usr/bin/ls really does lose ls.
var commands map[string]func(*Env) int

func init() {
	commands = map[string]func(*Env) int{
		// files
		"ls": cmdLs, "dir": cmdLs, "cat": cmdCat, "touch": cmdTouch, "mkdir": cmdMkdir, "rmdir": cmdRmdir,
		"rm": cmdRm, "cp": cmdCp, "mv": cmdCp, "ln": cmdLn, "chmod": cmdChmod, "chown": cmdChown,
		"chgrp": cmdChown, "chattr": cmdChattr, "lsattr": func(*Env) int { return 0 }, "stat": cmdStat,
		"file": cmdFile, "find": cmdFind, "du": cmdDu, "readlink": cmdReadlink, "realpath": cmdReadlink,
		"basename": cmdBasename, "dirname": cmdDirname, "which": cmdWhich, "whereis": cmdWhereis,
		"less": cmdCat, "more": cmdCat, "tar": cmdArchive, "gzip": cmdArchive, "gunzip": cmdArchive,
		"unzip": cmdArchive, "dd": cmdDd, "shred": cmdRm,

		// text
		"echo": builtinEcho, "printf": builtinPrintf, "head": cmdHead, "tail": cmdTail, "wc": cmdWc,
		"grep": cmdGrep, "egrep": cmdGrep, "fgrep": cmdGrep, "sort": cmdSort, "uniq": cmdUniq,
		"cut": cmdCut, "tr": cmdTr, "tee": cmdTee, "awk": cmdAwk, "gawk": cmdAwk, "sed": cmdSed,
		"xargs": cmdXargs, "base64": cmdBase64, "md5sum": cmdHashsum, "sha1sum": cmdHashsum,
		"sha256sum": cmdHashsum, "seq": cmdSeq, "yes": cmdYes, "rev": cmdRev,

		// system
		"ps": cmdPs, "top": cmdTop, "htop": cmdTop, "uptime": cmdUptime, "w": cmdW, "who": cmdW,
		"last": cmdLast, "whoami": cmdWhoami, "id": cmdId, "groups": cmdGroups, "hostname": cmdHostname,
		"uname": cmdUname, "free": cmdFree, "df": cmdDf, "nproc": cmdNproc, "lscpu": cmdLscpu,
		"lsb_release": cmdLsbRelease, "hostnamectl": cmdHostnamectl, "date": cmdDate, "sleep": cmdSleep,
		"env": cmdEnv, "printenv": cmdEnv, "clear": cmdClear, "reset": cmdClear, "crontab": cmdCrontab,
		"systemctl": cmdSystemctl, "service": cmdService, "apt": cmdApt, "apt-get": cmdApt,
		"dmesg": cmdDmesg, "lsblk": cmdLsblk, "mount": cmdMount, "reboot": cmdReboot,
		"shutdown": cmdReboot, "poweroff": cmdReboot, "halt": cmdReboot, "useradd": cmdUseradd,
		"adduser": cmdUseradd, "usermod": cmdUseradd, "chpasswd": cmdChpasswd, "passwd": cmdPasswd,
		"sudo": cmdSudo, "su": cmdSu, "sh": cmdShell, "bash": cmdShell, "dash": cmdShell,
		"python": cmdInterpreter, "python3": cmdInterpreter, "perl": cmdInterpreter,
		"vi": cmdEditor, "vim": cmdEditor, "nano": cmdEditor, "nohup": cmdNohup, "timeout": cmdTimeout,
		"true": func(*Env) int { return 0 }, "false": func(*Env) int { return 1 },
		"kill": builtinKill, "pkill": func(*Env) int { return 1 }, "killall": func(*Env) int { return 1 },
		"pwd": builtinPwd, "test": builtinTest,

		// network
		"wget": cmdWget, "curl": cmdCurl, "ping": cmdPing, "ifconfig": cmdIfconfig, "ip": cmdIP,
		"netstat": cmdNetstat, "ss": cmdNetstat, "ssh": cmdSSH, "scp": cmdSSH, "nc": cmdNc,
		"telnet": cmdNc, "iptables": cmdIptables,
	}
}

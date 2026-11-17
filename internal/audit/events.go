package audit

// Event names, as they appear in the "msg" field of the log. Each event
// also carries "session" and "remote" (the client address).
const (
	// Connect: a TCP connection was accepted.
	Connect = "connect"
	// Disconnect is logged when the TCP connection closes.
	Disconnect = "disconnect"
	// Forward is a port forwarding request (ssh -L, -D, -R). Nothing is
	// ever connected.
	Forward = "forward"
	// Auth: a login attempt. Fields: user, client_version, method,
	// success, and password, or key_type/fingerprint/key.
	Auth = "auth"
	// SessionStart: fields user, client_version, pty, term, width,
	// height, command (for exec requests), env.
	SessionStart = "session_start"
	// SessionEnd: fields exit_code, duration_s.
	SessionEnd = "session_end"
	// SessionRejected: the session limit was reached.
	SessionRejected = "session_rejected"

	// Input: a command line typed at the prompt or sent as an exec request.
	Input = "input"
	// Stdin: a line read by a running command (cat, read, python, ...).
	Stdin = "stdin"
	// Panic: a bug in a simulated command; the attacker saw a segfault.
	Panic = "panic"

	// PasswordEntered: typed at a sudo, su or adduser prompt.
	PasswordEntered = "password_entered"
	// PasswordChange: set with passwd or chpasswd.
	PasswordChange = "password_change"

	// Download: wget or curl. Fields tool, url, dest, post_data.
	Download = "download"
	// ExecBinary: a dropped binary was run (it "segfaults").
	ExecBinary = "exec_binary"
	// ExecScript: a script file was run; content has its text.
	ExecScript = "exec_script"
	// ExecInline: code run with sh -c, python -c, or piped into a shell.
	ExecInline = "exec_inline"

	// CrontabInstall: a crontab was installed; content has its text.
	CrontabInstall = "crontab_install"
	// UserAdd: useradd or adduser.
	UserAdd = "user_add"
	// UserModify: usermod.
	UserModify = "user_modify"
	// ServiceChange: systemctl start/stop/enable/...
	ServiceChange = "service_change"
	// FirewallChange: iptables.
	FirewallChange = "firewall_change"
	// PackageInstall: apt install.
	PackageInstall = "package_install"
	// Reboot: reboot, shutdown, poweroff.
	Reboot = "reboot"
	// LateralMovement: ssh or scp to another host.
	LateralMovement = "lateral_movement"
	// NetworkTool: nc or telnet.
	NetworkTool = "network_tool"
	// EditorOpen: vi, vim or nano on a file.
	EditorOpen = "editor_open"
	// ArchiveExtract: tar x.
	ArchiveExtract = "archive_extract"
)

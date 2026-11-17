# Run ssham on port 22 with Docker

Two steps: move your real SSH out of the way, then put ssham on port 22.

## 1. Move your real SSH to port 2200

> Do this first, or you will lock yourself out.

Open the new port in your firewall. If your cloud provider has a firewall or security
group, open 2200 there too.

```sh
sudo ufw allow 2200/tcp
```

Set `Port 2200` in `/etc/ssh/sshd_config`, then restart SSH:

```sh
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket   # Ubuntu 22.10 and newer
sudo systemctl restart ssh          # other systems
```

From a **new** terminal, check that you can still get in:

```sh
ssh -p 2200 you@your-server
```

Keep your old session open until this works.

## 2. Start ssham

```sh
git clone https://github.com/antonmedv/ssham && cd ssham
mkdir data && sudo chown 65532:65532 data
docker compose up -d
```

That's it. Port 22 now belongs to ssham.

## Watch the bots

```sh
sudo tail -f data/ssham.jsonl
```

Top passwords:

```sh
sudo jq -r 'select(.msg=="auth") | .password // empty' data/ssham.jsonl | sort | uniq -c | sort -rn | head
```

## Why it's safe

- ssham never runs real commands. Everything is fake and lives in memory.
- The container runs as a non-root user, with a read-only filesystem, no Linux
  capabilities, and no way to gain privileges.
- The only writable path is `./data`, which holds the host key and the log.
- Memory, CPU and process limits stop a flood of bots from hurting your server.

## Update

```sh
git pull && docker compose up -d --build
```

The host key in `./data` stays the same, so returning bots see the same server.

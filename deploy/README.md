# Running Aegis on a server

Five containers, defined in [compose.yaml](compose.yaml):

| Container | Job | Can reach |
| --- | --- | --- |
| `aegis` | The review server and dashboard | the database, the reviewer, and the internet (GitHub, the AI provider, OSV.dev) |
| `reviewer` | Reads users' code, one sealed process per review | **nothing**: no network at all, only a private socket shared with `aegis` |
| `postgres` | Review history | only `aegis` and `backup`; no internet |
| `backup` | A copy of the database every night, 14 kept | only `postgres` |
| `cloudflared` | The tunnel: the only way in | Cloudflare, and `aegis` |

Nothing listens on the server's own address. Every container runs without
administrator rights, cannot gain them, and has a memory cap. `aegis` and
`reviewer` also have read-only disks. All of this was tested on a laptop
first: a review through every container, the reviewer unable to reach the
internet or the database, the database unable to reach the internet, no ports
open, and a backup restored.

## First-time setup

**You need:** a server with Ubuntu 24.04 (2 CPUs, 4 GB memory), your SSH key
added when it is created, a domain on Cloudflare, and this Mac's `.env` and
`github-app.pem` for reference.

1. **Firewall.** In the provider's dashboard, allow incoming SSH (port 22)
   only. The tunnel connects outwards, so nothing else needs to be open.

2. **Log in and install Docker** (Docker's official packages for Ubuntu):
   ```bash
   ssh root@<server-address>
   apt-get update && apt-get install -y ca-certificates curl git
   install -m 0755 -d /etc/apt/keyrings
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
   apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```
   Ubuntu installs security updates automatically by default. Leave that on.

3. **A little swap space**, so a memory spike slows the server rather than
   stopping it:
   ```bash
   fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
   echo '/swapfile none swap sw 0 0' >> /etc/fstab
   ```

4. **Get the code.** The repository is private, so the server needs read-only
   access. Create a key on the server (`ssh-keygen -t ed25519`, press Enter
   three times), then add the contents of `~/.ssh/id_ed25519.pub` to the
   repository on GitHub under Settings → Deploy keys, **without** write access.
   ```bash
   git clone git@github.com:yalinGenc704/aegis.git ~/aegis
   ```

5. **The Cloudflare tunnel.** In Cloudflare's dashboard: Zero Trust → Networks →
   Tunnels → Create a tunnel → Cloudflared. Copy the token it shows. Under
   *Public hostname*, add `aegis.<your-domain>` pointing to `http://aegis:3000`.

6. **Settings and the App key.** Settings go in `deploy/.env` on the server only:
   ```bash
   cd ~/aegis/deploy
   cp .env.production.example .env && chmod 600 .env
   sed -i "s/<generate-me>/$(openssl rand -hex 32)/" .env
   nano .env    # PUBLIC_URL, CLOUDFLARE_TUNNEL_TOKEN, GITHUB_WEBHOOK_SECRET, optionally ANTHROPIC_API_KEY
   ```
   Copy the App key from the Mac (run this **on the Mac**):
   ```bash
   scp "/Users/yalingenc/Documents/Inspirit AI Project/aegis/github-app.pem" root@<server-address>:aegis/deploy/secrets/github-app.pem
   ```
   Then make it readable by the container's user only (on the server):
   ```bash
   chown 1000:1000 ~/aegis/deploy/secrets/github-app.pem && chmod 400 ~/aegis/deploy/secrets/github-app.pem
   ```

7. **Start it:**
   ```bash
   cd ~/aegis/deploy && docker compose up -d --build && docker compose ps
   ```
   All five should say `Up`, and `aegis` should say `healthy` within a minute.

8. **Point GitHub at it.** In the App's settings, set the webhook URL to
   `https://aegis.<your-domain>/api/github/webhook`. That is the last time it
   changes.

9. **Rate limiting** (Cloudflare → your domain → Security → WAF → Rate
   limiting rules): limit requests to `/api/` per visitor. Behind the tunnel the
   server cannot see visitors' addresses, so this is the place for it.

## Day to day

- **Update to the latest version:** `sh ~/aegis/deploy/update.sh`
- **See what is running:** `cd ~/aegis/deploy && docker compose ps`
- **Read the logs:** `docker compose logs --tail 100 aegis`
- **Stop everything:** `docker compose down` (keeps the data; `down -v` deletes it)

## Backups

Every night `backup` writes `aegis-<date>.dump` into the `backups` volume and
deletes copies older than 14 days. **These copies live on the same server**, so
they protect against mistakes, not against losing the server. For that, switch
on the provider's own server backups, or copy the files elsewhere. That choice
is still open.

**Restore** (replaces the current history with a backup):
```bash
cd ~/aegis/deploy
docker compose exec backup ls /backups
docker compose stop aegis
docker compose exec backup pg_restore --clean --if-exists -d aegis /backups/aegis-<date>.dump
docker compose start aegis
```

## Trying it on a laptop

`compose.local-test.yaml` switches the folder review on against
`server/test/deploy-samples` and opens the server on `127.0.0.1:3200`, so a
review can be sent through every container. Use throwaway values in
`deploy/.env` and a throwaway key, and delete both afterwards. Never use that
file on a server.

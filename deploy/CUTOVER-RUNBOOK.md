# ladder-script.org cutover runbook

Step-by-step procedure for bringing the neutral Ladder Script / QABIO
site live at `ladder-script.org`, independent of `bitcoinghost.org`
and the ghost-fork infrastructure.

Context: the old labs tree lives at `bitcoinghost.org/labs/` on
ghost-web, co-located with the ghost-fork project materials. We're
moving Ladder Script onto its own sovereign infrastructure so the
project stops being visually/organisationally associated with the
ghost-fork altcoin. The target machine is `ghost-labs`
(`85.9.213.194`), the same box that already runs the signet node and
the `ladder-proxy` Python service — so the new vhost's
`/api/ladder/*` reverse proxy is a localhost hop rather than a
public-internet round trip.

Backend changes: **none** beyond installing nginx. The ladder-proxy
continues to bind `0.0.0.0:8340`, so `bitcoinghost.org/api/ladder/*`
keeps working unchanged over the public internet. Both domains hit
the same Python service; only the front door is new.

## Prerequisites

- DNS: `ladder-script.org` and `www.ladder-script.org` A records
  point at `85.9.213.194` (ghost-labs public IPv4).
- SSH access: local `~/.ssh/config` has a `ghost-labs` alias with
  passwordless sudo.
- The `ladder-proxy.service` is running on ghost-labs and listening
  on `0.0.0.0:8340` (verify with
  `ssh ghost-labs sudo ss -tlnp "sport = :8340"`).
- Current working directory for all commands below:
  `/home/defenwycke/dev/projects/ghost-labs-ladder-script`.

## Cutover steps

### 1. Verify DNS has propagated

```
dig +short ladder-script.org
dig +short www.ladder-script.org
```

Both must resolve to `85.9.213.194`. If they don't yet, wait —
running certbot against an unresolved domain fails hard and
rate-limits for an hour.

### 2. Install nginx on ghost-labs

```
./deploy/deploy-ladder-script.sh prep
```

This runs `sudo apt install -y nginx` on ghost-labs and enables the
service. Idempotent — skips if nginx is already installed. Safe to
run even if you're unsure about the current state of the box.

### 3. Install the vhost (HTTP only, no TLS yet)

```
./deploy/deploy-ladder-script.sh nginx
```

This copies `deploy/nginx-ladder-script.conf` to
`/etc/nginx/sites-available/ladder-script`, symlinks it into
`sites-enabled/`, creates `/var/www/ladder-script`, runs `nginx -t`,
and reloads nginx.

At this point `http://ladder-script.org/` serves a 404 from the empty
webroot — that's expected. The vhost is live on port 80 only.

### 4. Sync the labs tree

```
./deploy/deploy-ladder-script.sh web
```

Rsyncs the `tools/` directory to `/var/www/ladder-script/` with
`--delete`, mirrors `block-docs/` to both `block-docs/` and
`docs/blocks/` (engine expects both paths — same quirk as the
bitcoinghost.org deploy), and fixes ownership to `www-data`.

Verify in a browser:

- `http://ladder-script.org/` → landing page
- `http://ladder-script.org/ladder-engine/` → Ladder Engine playground
- `http://ladder-script.org/qabio-playground/` → QABIO playground

### 5. Issue TLS certificate

```
ssh ghost-labs sudo apt install -y certbot python3-certbot-nginx
ssh ghost-labs sudo certbot --nginx \
    -d ladder-script.org -d www.ladder-script.org
```

Certbot isn't pre-installed on ghost-labs, so the first line
installs it and the nginx plugin. The second line edits
`/etc/nginx/sites-available/ladder-script` in place to add the
`listen 443 ssl` block, the certificate paths, and an HTTP → HTTPS
redirect server block. Accept the redirect option when prompted.

### 6. Verify the signet proxy path works

```
./deploy/deploy-ladder-script.sh smoke
```

Hits `https://ladder-script.org/api/ladder/status` and checks for HTTP
200. Should return the same JSON that `bitcoinghost.org/api/ladder/status`
returns (they share an upstream).

Manual cross-check:

```
curl -s https://bitcoinghost.org/api/ladder/status | python3 -m json.tool
curl -s https://ladder-script.org/api/ladder/status | python3 -m json.tool
```

Both should report the same signet tip.

### 7. Verify rate-limit isolation

The new vhost has its own `ladder_script_api` rate-limit zone, and
`bitcoinghost.org`'s nginx has its own zone on ghost-web. Load on
one domain cannot starve the other — they're not even on the same
machine:

```
for i in $(seq 1 50); do
    curl -s -o /dev/null -w "%{http_code}\n" \
        https://ladder-script.org/api/ladder/status
done
```

Expect 50x 200. Then immediately:

```
curl -s -o /dev/null -w "%{http_code}\n" \
    https://bitcoinghost.org/api/ladder/status
```

Also 200 — `bitcoinghost.org`'s rate-limit zone is unaffected.

### 8. Post-cutover housekeeping

After the new domain is live and serving content, audit external
references to the old host:

- `README.md` — mention `ladder-script.org` as the canonical home.
- `tools/index.html` and other landing pages — update any
  "hosted at bitcoinghost.org/labs" language.
- Any external announcements, README badges, or docs that point at
  `bitcoinghost.org/labs/*` — rewrite to `ladder-script.org/*`.

## Rollback

If something is broken and the new site needs to come down fast:

```
ssh ghost-labs sudo rm /etc/nginx/sites-enabled/ladder-script
ssh ghost-labs sudo nginx -t
ssh ghost-labs sudo systemctl reload nginx
```

DNS stays pointed at ghost-labs but nginx returns the default vhost
(or 404) until the symlink is restored. No impact on the
`ladder-proxy.service` — the reverse proxy is gone, but the Python
service on port 8340 is still running and `bitcoinghost.org/api/ladder/*`
continues to reach it over the public internet.

For a harder rollback (uninstall nginx entirely):

```
ssh ghost-labs sudo systemctl stop nginx
ssh ghost-labs sudo apt purge -y nginx nginx-common
```

Leaves ghost-labs in its pre-cutover state (ladder-proxy on 8340,
nothing on 80/443).

## Post-cutover

- Leave the old `bitcoinghost.org/labs` tree in place for the
  transition period — any existing external links will keep
  working, and `bitcoinghost.org/api/ladder/*` is still a valid
  access path to the same signet backend.
- Schedule a 30-day deprecation notice on the ghost-web `labs`
  landing page: "Ladder Script and QABIO have moved to
  ladder-script.org."
- Once traffic has fully migrated and no one is hitting
  `bitcoinghost.org/labs/*` organically, consider tightening the
  ladder-proxy binding on ghost-labs from `0.0.0.0:8340` to
  `127.0.0.1:8340`. That would break `bitcoinghost.org/api/ladder/*`
  as a side effect, so it should be a deliberate later step, not
  part of this cutover.

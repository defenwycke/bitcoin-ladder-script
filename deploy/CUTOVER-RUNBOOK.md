# ladder-script.org cutover runbook

Step-by-step procedure for bringing the neutral Ladder Script / QABIO
site live at `ladder-script.org`, independent of `bitcoinghost.org`.

Context: Ladder Script is a BIP draft for Bitcoin. The old labs tree
lives at `bitcoinghost.org/labs/` on the ghost-web host, co-located with
the ghost-fork project materials. For BIP submission we want a neutral
project-specific home so reviewers land on Ladder Script / QABIO
content without the altcoin association. This runbook sets up that
neutral home on the same web host, sharing the same signet RPC backend
(`85.9.213.194:8340`) via a new reverse-proxy path.

Backend changes: **none**. The ladder-proxy already CORS-allows `*`, and
the new vhost points at the same upstream as `bitcoinghost.org/api/ladder/`.
Only the public-facing front door is new.

## Prerequisites

- DNS: `ladder-script.org` and `www.ladder-script.org` A records point
  at the ghost-web public IP (`83.136.255.218`).
- SSH access: local `~/.ssh/config` has `ghost-web` alias with sudo.
- Certbot is already installed on ghost-web (used for
  `bitcoinghost.org`).
- Current working directory for all commands below:
  `/home/defenwycke/dev/projects/ghost-labs-ladder-script`.

## Cutover steps

### 1. Verify DNS has propagated

```
dig +short ladder-script.org
dig +short www.ladder-script.org
```

Both must resolve to the ghost-web public IP. If they don't yet, wait
— running certbot against an unresolved domain fails hard and rate-limits.

### 2. Install the vhost (HTTP only, no TLS yet)

```
./deploy/deploy-ladder-script.sh nginx
```

This copies `deploy/nginx-ladder-script.conf` to
`/etc/nginx/sites-available/ladder-script`, symlinks it into
`sites-enabled/`, creates `/var/www/ladder-script`, runs `nginx -t`,
and reloads nginx.

At this point `http://ladder-script.org/` serves a 404 from the empty
webroot — that's expected. The vhost is live on port 80 only.

### 3. Sync the labs tree

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

### 4. Issue TLS certificate

```
ssh ghost-web sudo certbot --nginx \
    -d ladder-script.org -d www.ladder-script.org
```

Certbot will edit `/etc/nginx/sites-available/ladder-script` in place
to add the `listen 443 ssl` block, the certificate paths, and an HTTP
→ HTTPS redirect server block. Accept the redirect option when
prompted.

### 5. Verify the signet proxy path works

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

### 6. Verify rate-limit isolation

The new vhost has its own `ladder_script_api` rate-limit zone, so load
on one domain cannot starve the other:

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

Also 200 — `bitcoinghost.org`'s `ladder_api` zone is unaffected.

### 7. Update BIP drafts and external links

After the new domain is live and serving content:

- `docs/BIP-XXXX.md` — confirm the "live playground" and "block
  documentation" links point to `ladder-script.org/*`.
- `docs/BIP-YYYY.md` — same.
- `README.md` — add a "Hosted at" line.

These edits live on the `rebrand-ladder-script` branch and should
already be in place from the rebrand pass; this step is a verification,
not a fresh write.

## Rollback

If something is broken and the new site needs to come down fast:

```
ssh ghost-web sudo rm /etc/nginx/sites-enabled/ladder-script
ssh ghost-web sudo nginx -t
ssh ghost-web sudo systemctl reload nginx
```

DNS stays pointed at ghost-web but returns the nginx default vhost
until the symlink is restored. No impact on `bitcoinghost.org`.

## Post-cutover

- Point the BIP submission PR description at `ladder-script.org`, not
  `bitcoinghost.org/labs`.
- Leave the old `bitcoinghost.org/labs` tree in place for the
  transition period — the old links in existing comments will keep
  working.
- Schedule a 30-day deprecation notice on the ghost-web `labs` landing
  page: "Ladder Script and QABIO have moved to ladder-script.org."

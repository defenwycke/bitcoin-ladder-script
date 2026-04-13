#!/bin/bash
set -euo pipefail

# Deploy the ladder-script.org site. This is the neutral, project-specific
# home for Ladder Script and QABIO — separate from bitcoinghost.org, which
# hosts the ghost-fork materials.
#
# Targets:
#   web      — rsync labs tree to /var/www/ladder-script on the web host
#   nginx    — push the vhost config and reload nginx
#   smoke    — curl the signet proxy through the new hostname
#   all      — nginx + web + smoke
#
# Usage: ./deploy/deploy-ladder-script.sh [web|nginx|smoke|all]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

WEB_HOST="ghost-web"
WEB_ROOT="/var/www/ladder-script"
VHOST_NAME="ladder-script"
VHOST_SRC="$SCRIPT_DIR/nginx-ladder-script.conf"
SMOKE_URL="https://ladder-script.org/api/ladder/status"

TARGET="${1:-all}"

confirm() {
    local msg="$1"
    printf "\n%s [y/N] " "$msg"
    read -r answer
    case "$answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Nginx vhost ──────────────────────────────────────────────────────────

deploy_nginx() {
    echo "=== Deploy nginx vhost for $VHOST_NAME ==="
    if [ ! -f "$VHOST_SRC" ]; then
        echo "ERROR: $VHOST_SRC not found"
        exit 1
    fi
    confirm "Install $VHOST_NAME vhost on $WEB_HOST and reload nginx?" || return 0

    echo "--- Uploading vhost ---"
    scp "$VHOST_SRC" "$WEB_HOST:/tmp/$VHOST_NAME.conf"

    ssh "$WEB_HOST" bash <<REMOTE
set -euo pipefail
sudo mkdir -p $WEB_ROOT
sudo chown www-data:www-data $WEB_ROOT
sudo cp /tmp/$VHOST_NAME.conf /etc/nginx/sites-available/$VHOST_NAME
sudo chmod 644 /etc/nginx/sites-available/$VHOST_NAME
if [ ! -L /etc/nginx/sites-enabled/$VHOST_NAME ]; then
    sudo ln -s /etc/nginx/sites-available/$VHOST_NAME /etc/nginx/sites-enabled/$VHOST_NAME
fi
rm /tmp/$VHOST_NAME.conf
sudo nginx -t
sudo systemctl reload nginx
echo "nginx reloaded."
REMOTE

    echo ""
    echo "Vhost installed. Remember to run certbot if TLS is not yet active:"
    echo "  ssh $WEB_HOST sudo certbot --nginx -d ladder-script.org -d www.ladder-script.org"
}

# ── Labs tree rsync ──────────────────────────────────────────────────────

deploy_web() {
    echo "=== Sync labs tree to $WEB_HOST:$WEB_ROOT ==="
    confirm "Rsync labs tree to $WEB_HOST:$WEB_ROOT?" || return 0

    ssh "$WEB_HOST" "sudo mkdir -p $WEB_ROOT && sudo chown -R $USER:$USER $WEB_ROOT"

    echo "--- Landing page and tools ---"
    rsync -avz --delete \
        --exclude='.git/' \
        --exclude='node_modules/' \
        --exclude='*.swp' \
        "$ROOT/tools/" "$WEB_HOST:$WEB_ROOT/"

    echo "--- Docs SPA ---"
    if [ -d "$ROOT/tools/docs" ]; then
        ssh "$WEB_HOST" "sudo mkdir -p $WEB_ROOT/docs/blocks"
        rsync -avz "$ROOT/tools/block-docs/" "$WEB_HOST:$WEB_ROOT/block-docs/"
        rsync -avz "$ROOT/tools/block-docs/" "$WEB_HOST:$WEB_ROOT/docs/blocks/"
    fi

    echo "--- Fixing ownership ---"
    ssh "$WEB_HOST" "sudo chown -R www-data:www-data $WEB_ROOT && sudo find $WEB_ROOT -type f -exec chmod 644 {} \; && sudo find $WEB_ROOT -type d -exec chmod 755 {} \;"

    echo ""
    echo "Labs tree synced."
}

# ── Smoke test ───────────────────────────────────────────────────────────

smoke_test() {
    echo "=== Smoke test ==="
    echo "  Checking: $SMOKE_URL"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$SMOKE_URL" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
        echo "  Status: OK (HTTP 200)"
        curl -s "$SMOKE_URL" 2>/dev/null | python3 -m json.tool 2>/dev/null || curl -s "$SMOKE_URL"
    else
        echo "  Status: HTTP $http_code"
        echo "  (If 404/502 before DNS+TLS are live, this is expected.)"
        return 1
    fi
}

case "$TARGET" in
    web)    deploy_web ;;
    nginx)  deploy_nginx ;;
    smoke)  smoke_test ;;
    all)
        deploy_nginx
        deploy_web
        echo ""
        smoke_test || true
        ;;
    *)
        echo "Usage: $0 [web|nginx|smoke|all]"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="

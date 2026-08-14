#!/usr/bin/env bash
# av-deploy.sh — deploy the freeq AV / QUIC stack to the production server.
#
# Run from a laptop checkout of freeq. Pushes the current branch, then over
# SSH: pulls, builds freeq-server (+ the web app), restarts the service, and
# health-checks the SFU. Also handles the one-time TLS cert plumbing the
# SFU's QUIC/WebTransport listener needs.
#
# See docs/AV-QUIC-MIGRATION.md for the full plan.
#
# Usage:
#   deploy/av-deploy.sh [cert|deploy|verify|all]
#     cert    one-time: copy the Let's Encrypt cert to a freeq-server-readable
#             path and install a certbot renewal hook (idempotent)
#     deploy  push, then pull + build + restart on the server
#     verify  health-check the SFU (service, ports, cert, recent logs)
#     all     cert + deploy + verify   (default)
#
# Configure via environment (no host is baked into this script):
#   FREEQ_SERVER       ssh target              (required, e.g. deploy@irc.example.com)
#   FREEQ_CERT_DOMAIN  Let's Encrypt domain    (default: host part of FREEQ_SERVER)
#   FREEQ_REMOTE_USER  service account on host (default: user part of FREEQ_SERVER)
#   FREEQ_REMOTE_REPO  repo path on server     (default /srv/freeq)
#   FREEQ_CERT_DST     cert copy destination   (default /srv/freeq-certs)
#   FREEQ_QUIC_PORT    SFU QUIC/UDP port       (default 8080)
set -euo pipefail

SERVER="${FREEQ_SERVER:-}"
if [ -z "$SERVER" ]; then
  printf '\033[1;31m!! set FREEQ_SERVER (e.g. FREEQ_SERVER=deploy@irc.example.com %s)\033[0m\n' "$0" >&2
  exit 1
fi
REMOTE_USER="${FREEQ_REMOTE_USER:-${SERVER%%@*}}"
REMOTE_REPO="${FREEQ_REMOTE_REPO:-/srv/freeq}"
DOMAIN="${FREEQ_CERT_DOMAIN:-${SERVER##*@}}"
CERT_SRC="/etc/letsencrypt/live/${DOMAIN}"
CERT_DST="${FREEQ_CERT_DST:-/srv/freeq-certs}"
QUIC_PORT="${FREEQ_QUIC_PORT:-8080}"
SERVICE="freeq-server"

log()   { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
err()   { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; }
ssh_do() { ssh -o BatchMode=yes "$SERVER" "$@"; }

do_cert() {
  log "Cert: copying ${DOMAIN} cert into ${CERT_DST} (freeq-server-readable)"
  ssh_do "sudo install -d -o '${REMOTE_USER}' -g '${REMOTE_USER}' -m 700 '${CERT_DST}' \
    && sudo cp -L '${CERT_SRC}/fullchain.pem' '${CERT_SRC}/privkey.pem' '${CERT_DST}/' \
    && sudo chown '${REMOTE_USER}:${REMOTE_USER}' '${CERT_DST}'/*.pem \
    && sudo chmod 600 '${CERT_DST}'/*.pem \
    && ls -l '${CERT_DST}'"

  log "Cert: installing certbot renewal deploy-hook"
  ssh_do "sudo tee /etc/letsencrypt/renewal-hooks/deploy/freeq-av-cert.sh >/dev/null" <<HOOK
#!/bin/bash
# Installed by av-deploy.sh — re-copy the renewed cert for the freeq AV SFU
# and restart freeq-server so the QUIC listener picks it up.
set -e
cp -L /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${CERT_DST}/fullchain.pem
cp -L /etc/letsencrypt/live/${DOMAIN}/privkey.pem   ${CERT_DST}/privkey.pem
chown ${REMOTE_USER}:${REMOTE_USER} ${CERT_DST}/*.pem
chmod 600 ${CERT_DST}/*.pem
systemctl restart ${SERVICE}
HOOK
  ssh_do "sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/freeq-av-cert.sh"
  log "Cert: done. Ensure .env.secrets sets FREEQ_AV_TLS_CERT / FREEQ_AV_TLS_KEY"
  log "      (see docs/AV-QUIC-MIGRATION.md, Phase 1)."
}

do_deploy() {
  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"
  log "Deploy: pushing '${branch}' to origin"
  git push origin "${branch}"

  log "Deploy: pull + build + restart on ${SERVER}"
  ssh_do "set -e
    cd '${REMOTE_REPO}'
    git pull --ff-only
    echo '-- building freeq-server (release, av-native) --'
    cargo build --release --bin freeq-server --features av-native
    echo '-- building web app --'
    ( cd freeq-app && npm ci --silent && npm run build )
    echo '-- restarting ${SERVICE} --'
    sudo systemctl restart '${SERVICE}'"
}

do_verify() {
  log "Verify: SFU health on ${SERVER}"
  ssh_do "set -e
    echo '-- service --';  systemctl is-active '${SERVICE}'
    echo '-- ports --';    ss -tulpn 2>/dev/null | grep -E ':(${QUIC_PORT}|443|8080)\\b' || echo '(none matched)'
    echo '-- cert --';     ls -l '${CERT_DST}'/*.pem 2>/dev/null || echo 'NO CERT (run: av-deploy.sh cert)'
    echo '-- recent log --'; sudo journalctl -u '${SERVICE}' --no-pager -n 20 2>/dev/null | tail -20 || true"
}

main() {
  case "${1:-all}" in
    cert)   do_cert ;;
    deploy) do_deploy ;;
    verify) do_verify ;;
    all)    do_cert; do_deploy; do_verify ;;
    *) err "usage: $0 [cert|deploy|verify|all]"; exit 1 ;;
  esac
  log "av-deploy: done."
}

main "$@"

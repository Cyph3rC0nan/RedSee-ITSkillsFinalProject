#!/bin/bash
# docker/demo-helper.sh
# Starts demo containers (DVWA, Juice Shop) with one command.
# Usage: bash docker/demo-helper.sh [start|dvwa|juiceshop|marketplace|stop|status]
#   start        - DVWA + Juice Shop + the RedSee Flask dashboard (blocking, foreground)
#   dvwa         - DVWA only (detached), then prints the .env scope values + setup checklist
#   juiceshop    - Juice Shop only (detached)
#   marketplace  - RedSees Marketplace demo target: applies the cosmetic re-skin
#                  (demo-target/apply-reskin.sh — SCSS/logo/font themepack +
#                  frontend rebuild, skipped if already applied), starts the
#                  themed Juice Shop (NODE_CONFIG_ENV=redsees, local checkout,
#                  internal-only port) + the demo-target/ reflected-XSS companion
#                  service (internal-only port), then starts demo-target/gateway/
#                  — a reverse proxy that puts BOTH behind the single public
#                  JUICE_PORT (/market/* -> sinks, everything else -> Juice
#                  Shop), all on host networking, then prints the .env scope
#                  values (see docs/redsees_marketplace_vulns.txt for the
#                  ground-truth vuln map)
#   stop         - stop + remove both demo containers
#   status       - show running demo containers
#
# Config (env vars, all optional):
#   DVWA_PORT         - host port for DVWA           (default: 8080 -> container's 80)
#   JUICE_PORT        - host port for Juice Shop     (default: 3000 -> container's 3000)
#   DVWA_IMAGE        - DVWA image to pull           (default: vulnerables/web-dvwa)
#   DVWA_HOST         - hostname to print in the .env guidance below (default: redsees.com,
#                       matching this project's existing REDSEE_ALLOWED_HOSTS convention —
#                       override if your DVWA is reachable under a different name)
#   JUICE_SHOP_DIR    - path to the local Juice Shop checkout used by `marketplace`
#                       (default: /root/juice-shop) — must already be built
#                       (node_modules/ + build/app.js present; `npm install && npm run build`)
#   JUICE_INTERNAL_PORT - INTERNAL port the themed Juice Shop process actually binds
#                       for `marketplace` (default: 3001) — must match config/redsees.yml's
#                       `server.port`. Not reachable directly as "the" app; demo-target/gateway/
#                       fronts it on JUICE_PORT (see below).
#   MARKETPLACE_PORT  - INTERNAL port for the demo-target/ companion sink service
#                       (default: 8081, host networking — NOT a published bridge port).
#                       Since the gateway was added, this is no longer the port you point
#                       a scanner at — see JUICE_PORT / GATEWAY_PORT below.
#   MARKETPLACE_HOST  - hostname to print in the .env guidance for `marketplace`
#                       (default: redsees.com)
#   GATEWAY_PORT      - PUBLIC port demo-target/gateway/ listens on for `marketplace`;
#                       fronts both Juice Shop and the sink service on one port
#                       (default: same value as JUICE_PORT, i.e. 3000)
#   FORCE_RESKIN      - if "true", re-apply demo-target/apply-reskin.sh (themepack
#                       copy + frontend rebuild) even if it looks already applied
#                       (default: false — `marketplace` skips the rebuild when
#                       frontend/src/assets/public/redsees_favicon.ico already exists)

set -e

ACTION=${1:-start}
DVWA_PORT=${DVWA_PORT:-8080}
JUICE_PORT=${JUICE_PORT:-3000}
DVWA_IMAGE=${DVWA_IMAGE:-vulnerables/web-dvwa}
DVWA_HOST=${DVWA_HOST:-redsees.com}
JUICE_SHOP_DIR=${JUICE_SHOP_DIR:-/root/juice-shop}
JUICE_INTERNAL_PORT=${JUICE_INTERNAL_PORT:-3001}
MARKETPLACE_PORT=${MARKETPLACE_PORT:-8081}
MARKETPLACE_HOST=${MARKETPLACE_HOST:-redsees.com}
FORCE_RESKIN=${FORCE_RESKIN:-false}
GATEWAY_PORT=${GATEWAY_PORT:-$JUICE_PORT}
DEMO_TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/demo-target"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

_start_dvwa() {
  echo -e "${BLUE}Starting DVWA (Damn Vulnerable Web App)...${NC}"
  docker run -d \
    --name redsee-dvwa \
    --restart unless-stopped \
    -p ${DVWA_PORT}:80 \
    ${DVWA_IMAGE} 2>/dev/null || \
    docker start redsee-dvwa 2>/dev/null || \
    echo "DVWA already running"
}

_start_juiceshop() {
  echo -e "${BLUE}Starting OWASP Juice Shop...${NC}"
  docker run -d \
    --name redsee-juiceshop \
    --restart unless-stopped \
    -p ${JUICE_PORT}:3000 \
    bkimminich/juice-shop 2>/dev/null || \
    docker start redsee-juiceshop 2>/dev/null || \
    echo "Juice Shop already running"
}

# Prints the exact .env values for a DVWA scan + the browser-based first-run
# checklist DVWA needs (can't be scripted via HTTP alone: DB creation, login,
# and the Security-level cookie DVWA reads on every request).
_print_dvwa_scope() {
  echo ""
  echo -e "${GREEN}✅ DVWA started:${NC} http://localhost:${DVWA_PORT}"
  echo ""
  echo -e "${YELLOW}Add to .env for a DVWA scan:${NC}"
  echo "  REDSEE_TARGET_URL=http://${DVWA_HOST}:${DVWA_PORT}/"
  echo "  REDSEE_ALLOWED_HOSTS=${DVWA_HOST}"
  echo ""
  echo "  DVWA and Juice Shop are BOTH host-local (this same machine, just different"
  echo "  ports). engine/scope.py's allow-list matches on HOSTNAME only (not port), so"
  echo "  ONE entry — e.g. REDSEE_ALLOWED_HOSTS=${DVWA_HOST} — covers BOTH :${JUICE_PORT}"
  echo "  (Juice Shop) and :${DVWA_PORT} (DVWA), as long as that hostname resolves to"
  echo "  this host. If they resolve to DIFFERENT hostnames, list both, comma-separated:"
  echo "    REDSEE_ALLOWED_HOSTS=${DVWA_HOST},<other-host>"
  echo ""
  echo -e "${YELLOW}Post-launch checklist (one-time browser setup — DVWA can't be fully${NC}"
  echo -e "${YELLOW}scripted via HTTP alone):${NC}"
  echo "  1. Open http://localhost:${DVWA_PORT}/setup.php and click 'Create / Reset Database'"
  echo "  2. Log in at http://localhost:${DVWA_PORT}/login.php with admin / password"
  echo "     (DVWA's documented default creds — lab-only; never reuse a real password)"
  echo "  3. Left nav -> 'DVWA Security' -> set Security Level to 'Low'"
  echo "     (required for /vulnerabilities/xss_r/ to reflect the payload unescaped)"
  echo "  4. Reflected-XSS target: http://localhost:${DVWA_PORT}/vulnerabilities/xss_r/?name=..."
  echo "     This route requires an authenticated session — the scanner will need the"
  echo "     PHPSESSID + security=low cookies from steps 2-3 (wired in the next prompt)."
  echo ""
  echo -e "${YELLOW}Reachability check:${NC}"
  echo "  curl -s -o /dev/null -w \"%{http_code}\\n\" http://localhost:${DVWA_PORT}/   # expect 200/302"
  echo ""
}

# Applies demo-target/apply-reskin.sh (SCSS/logo/font themepack copy + frontend
# rebuild) unless it already looks applied. Deliberately skipped when Juice Shop
# is already running (nothing to rebuild into) and skippable via FORCE_RESKIN=true
# to force a reapply (e.g. after editing the themepack).
_ensure_reskin_applied() {
  local marker="${JUICE_SHOP_DIR}/frontend/src/assets/public/redsees_favicon.ico"
  if [ "$FORCE_RESKIN" = "true" ] || [ ! -f "$marker" ]; then
    echo -e "${BLUE}Applying RedSees Marketplace cosmetic re-skin (themepack + frontend rebuild)...${NC}"
    JUICE_SHOP_DIR="${JUICE_SHOP_DIR}" bash "${DEMO_TARGET_DIR}/apply-reskin.sh"
  else
    echo "Re-skin already applied (found ${marker}) — skipping rebuild. Set FORCE_RESKIN=true to reapply."
  fi
}

# Starts the local Juice Shop checkout (already built: node_modules/ + build/app.js)
# as a themed background process with NODE_CONFIG_ENV=redsees, which activates
# config/redsees.yml ("RedSees Marketplace" branding + catalog) inside that repo.
# Binds JUICE_INTERNAL_PORT (config/redsees.yml's server.port), NOT the public
# JUICE_PORT — demo-target/gateway/ fronts it on JUICE_PORT so it can share that
# port with the sink service. Runs as a host process, not a container —
# bkimminich/juice-shop (used by `juiceshop`/`start`) is the stock public image
# and does not contain this repo's config/redsees.yml overlay or the frontend re-skin.
_start_marketplace_juiceshop() {
  echo -e "${BLUE}Starting themed Juice Shop (RedSees Marketplace)...${NC}"
  if [ ! -f "${JUICE_SHOP_DIR}/build/app.js" ]; then
    echo -e "${RED}Juice Shop checkout not found/built at ${JUICE_SHOP_DIR}.${NC}"
    echo "  Set JUICE_SHOP_DIR to your checkout (must be built: npm install && npm run build)."
    return 1
  fi
  if curl -s -o /dev/null -w '%{http_code}' "http://localhost:${JUICE_INTERNAL_PORT}/" 2>/dev/null | grep -qE '200|304'; then
    echo "Juice Shop already running on internal :${JUICE_INTERNAL_PORT}"
  else
    _ensure_reskin_applied
    (cd "${JUICE_SHOP_DIR}" && NODE_CONFIG_ENV=redsees nohup node build/app.js \
      > /tmp/redsees-juiceshop.log 2>&1 & echo $! > /tmp/redsees-juiceshop.pid)
    sleep 2
    echo "Themed Juice Shop starting on internal :${JUICE_INTERNAL_PORT} (logs: /tmp/redsees-juiceshop.log)"
  fi
}

# Builds + starts the demo-target/ reflected-XSS companion service with HOST
# networking (--network host), never a published bridge port — a published/DNAT'd
# port is the sandbox-reachability blocker documented in HANDOFF.md. Binds
# MARKETPLACE_PORT internally; demo-target/gateway/ fronts it on JUICE_PORT.
_start_marketplace_sinks() {
  echo -e "${BLUE}Starting RedSees Marketplace companion sink service...${NC}"
  MARKETPLACE_PORT=${MARKETPLACE_PORT} docker build -t redsee-marketplace-sinks "${DEMO_TARGET_DIR}" >/dev/null
  docker run -d \
    --name redsee-marketplace-sinks \
    --restart unless-stopped \
    --network host \
    -e MARKETPLACE_PORT=${MARKETPLACE_PORT} \
    redsee-marketplace-sinks 2>/dev/null || \
    docker start redsee-marketplace-sinks 2>/dev/null || \
    echo "Marketplace sink service already running"
}

# Builds + starts demo-target/gateway/, the reverse proxy that puts Juice Shop
# and the sink service behind ONE public port (GATEWAY_PORT, same value as
# JUICE_PORT by default): /market/* -> the sink service, everything else ->
# Juice Shop. HOST networking, same reasoning as the sink service.
_start_marketplace_gateway() {
  echo -e "${BLUE}Starting RedSees Marketplace gateway (unified port ${GATEWAY_PORT})...${NC}"
  docker build -t redsee-marketplace-gateway "${DEMO_TARGET_DIR}/gateway" >/dev/null
  docker run -d \
    --name redsee-marketplace-gateway \
    --restart unless-stopped \
    --network host \
    -e GATEWAY_PORT=${GATEWAY_PORT} \
    -e JUICE_SHOP_TARGET="http://127.0.0.1:${JUICE_INTERNAL_PORT}" \
    -e MARKETPLACE_SINKS_TARGET="http://127.0.0.1:${MARKETPLACE_PORT}" \
    redsee-marketplace-gateway 2>/dev/null || \
    docker start redsee-marketplace-gateway 2>/dev/null || \
    echo "Marketplace gateway already running"
}

_print_marketplace_scope() {
  echo ""
  echo -e "${GREEN}✅ RedSees Marketplace started:${NC}"
  echo "  Unified entry point: http://localhost:${GATEWAY_PORT}/         (Juice Shop storefront)"
  echo "                       http://localhost:${GATEWAY_PORT}/market/  (companion sinks, same port)"
  echo "  (internal-only — not meant to be hit directly: Juice Shop :${JUICE_INTERNAL_PORT}, sinks :${MARKETPLACE_PORT})"
  echo ""
  echo -e "${YELLOW}Add to .env for a RedSees Marketplace scan:${NC}"
  echo "  REDSEE_TARGET_URL=http://${MARKETPLACE_HOST}:${GATEWAY_PORT}/market/"
  echo "  REDSEE_ALLOWED_HOSTS=${MARKETPLACE_HOST}"
  echo ""
  echo "  Ground-truth vuln map: docs/redsees_marketplace_vulns.txt"
  echo ""
  echo -e "${YELLOW}Reachability check:${NC}"
  echo "  curl -s 'http://${MARKETPLACE_HOST}:${GATEWAY_PORT}/market/search?q=<b>PWN</b>' | grep '<b>PWN</b>'"
  echo ""
}

case "$ACTION" in
  start)
    echo -e "${RED}🛡️  RedSee Demo Setup${NC}"
    echo "================================"

    _start_dvwa
    _start_juiceshop
    _print_dvwa_scope

    echo -e "${GREEN}✅ Demo targets started:${NC}"
    echo "  DVWA:       http://localhost:${DVWA_PORT}"
    echo "  Juice Shop: http://localhost:${JUICE_PORT}"
    echo ""
    echo -e "${BLUE}Starting RedSee Flask server...${NC}"
    echo "  Dashboard:  http://localhost:5000"
    echo ""
    python app.py
    ;;

  dvwa)
    echo -e "${RED}🛡️  RedSee Demo Setup — DVWA only${NC}"
    echo "================================"
    _start_dvwa
    _print_dvwa_scope
    ;;

  juiceshop)
    echo -e "${RED}🛡️  RedSee Demo Setup — Juice Shop only${NC}"
    echo "================================"
    _start_juiceshop
    echo ""
    echo -e "${GREEN}✅ Juice Shop started:${NC} http://localhost:${JUICE_PORT}"
    ;;

  marketplace)
    echo -e "${RED}🛡️  RedSee Demo Setup — RedSees Marketplace${NC}"
    echo "================================"
    _start_marketplace_juiceshop
    _start_marketplace_sinks
    _start_marketplace_gateway
    _print_marketplace_scope
    ;;

  stop)
    echo "Stopping RedSee demo containers..."
    docker stop redsee-dvwa redsee-juiceshop 2>/dev/null || true
    docker rm redsee-dvwa redsee-juiceshop 2>/dev/null || true
    docker stop redsee-marketplace-sinks redsee-marketplace-gateway 2>/dev/null || true
    docker rm redsee-marketplace-sinks redsee-marketplace-gateway 2>/dev/null || true
    if [ -f /tmp/redsees-juiceshop.pid ]; then
      kill "$(cat /tmp/redsees-juiceshop.pid)" 2>/dev/null || true
      rm -f /tmp/redsees-juiceshop.pid
    fi
    echo "✅ Done"
    ;;

  status)
    echo "Container status:"
    docker ps --filter "name=redsee-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    ;;

  *)
    echo "Usage: $0 [start|dvwa|juiceshop|marketplace|stop|status]"
    exit 1
    ;;
esac

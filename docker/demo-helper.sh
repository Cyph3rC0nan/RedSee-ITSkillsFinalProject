#!/bin/bash
# docker/demo-helper.sh
# Starts demo containers (DVWA, Juice Shop) with one command.
# Usage: bash docker/demo-helper.sh [start|dvwa|juiceshop|stop|status]
#   start      - DVWA + Juice Shop + the RedSee Flask dashboard (blocking, foreground)
#   dvwa       - DVWA only (detached), then prints the .env scope values + setup checklist
#   juiceshop  - Juice Shop only (detached)
#   stop       - stop + remove both demo containers
#   status     - show running demo containers
#
# Config (env vars, all optional):
#   DVWA_PORT   - host port for DVWA          (default: 8080 -> container's 80)
#   JUICE_PORT  - host port for Juice Shop    (default: 3000 -> container's 3000)
#   DVWA_IMAGE  - DVWA image to pull          (default: vulnerables/web-dvwa)
#   DVWA_HOST   - hostname to print in the .env guidance below (default: redsees.com,
#                 matching this project's existing REDSEE_ALLOWED_HOSTS convention —
#                 override if your DVWA is reachable under a different name)

set -e

ACTION=${1:-start}
DVWA_PORT=${DVWA_PORT:-8080}
JUICE_PORT=${JUICE_PORT:-3000}
DVWA_IMAGE=${DVWA_IMAGE:-vulnerables/web-dvwa}
DVWA_HOST=${DVWA_HOST:-redsees.com}

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

  stop)
    echo "Stopping RedSee demo containers..."
    docker stop redsee-dvwa redsee-juiceshop 2>/dev/null || true
    docker rm redsee-dvwa redsee-juiceshop 2>/dev/null || true
    echo "✅ Done"
    ;;

  status)
    echo "Container status:"
    docker ps --filter "name=redsee-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    ;;

  *)
    echo "Usage: $0 [start|dvwa|juiceshop|stop|status]"
    exit 1
    ;;
esac

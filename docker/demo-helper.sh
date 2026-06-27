#!/bin/bash
# docker/demo-helper.sh
# Starts all demo containers with one command.
# Usage: bash docker/demo-helper.sh [start|stop|status]

set -e

ACTION=${1:-start}
DVWA_PORT=${DVWA_PORT:-80}
JUICE_PORT=${JUICE_PORT:-3000}

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

case "$ACTION" in
  start)
    echo -e "${RED}🛡️  RedSee Demo Setup${NC}"
    echo "================================"

    echo -e "${BLUE}Starting DVWA (Damn Vulnerable Web App)...${NC}"
    docker run -d \
      --name redsee-dvwa \
      --restart unless-stopped \
      -p ${DVWA_PORT}:80 \
      vulnerables/web-dvwa 2>/dev/null || \
      docker start redsee-dvwa 2>/dev/null || \
      echo "DVWA already running"

    echo -e "${BLUE}Starting OWASP Juice Shop...${NC}"
    docker run -d \
      --name redsee-juiceshop \
      --restart unless-stopped \
      -p ${JUICE_PORT}:3000 \
      bkimminich/juice-shop 2>/dev/null || \
      docker start redsee-juiceshop 2>/dev/null || \
      echo "Juice Shop already running"

    echo ""
    echo -e "${GREEN}✅ Demo targets started:${NC}"
    echo "  DVWA:       http://localhost:${DVWA_PORT}"
    echo "  Juice Shop: http://localhost:${JUICE_PORT}"
    echo ""
    echo -e "${BLUE}Starting RedSee Flask server...${NC}"
    echo "  Dashboard:  http://localhost:5000"
    echo ""
    python app.py
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
    echo "Usage: $0 [start|stop|status]"
    exit 1
    ;;
esac

#!/bin/bash
# demo-target/apply-reskin.sh
# Applies the RedSees Marketplace cosmetic re-skin (demo-target/redsees-themepack/)
# onto a Juice Shop checkout's frontend source tree, then rebuilds the frontend.
# Idempotent: every step is a plain file copy (cp -f) followed by a full frontend
# build, so re-running this script against the same checkout reproduces the same
# result. COSMETIC ONLY — copies SCSS/HTML/font/image files; touches no route,
# API, or vulnerability code.
#
# Usage: bash demo-target/apply-reskin.sh
#
# Config (env vars, all optional):
#   JUICE_SHOP_DIR  - path to the Juice Shop checkout to re-skin (default: /root/juice-shop)
#   SKIP_BUILD      - if set to "true", copy the themepack files but skip the
#                      frontend build (useful for fast iteration on the SCSS itself;
#                      the re-skin will NOT be visible in a served app until built)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THEMEPACK="${SCRIPT_DIR}/redsees-themepack"
JUICE_SHOP_DIR=${JUICE_SHOP_DIR:-/root/juice-shop}
SKIP_BUILD=${SKIP_BUILD:-false}

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ ! -d "$THEMEPACK" ]; then
  echo -e "${RED}Themepack not found at ${THEMEPACK}.${NC}"
  exit 1
fi

if [ ! -f "${JUICE_SHOP_DIR}/package.json" ]; then
  echo -e "${RED}Juice Shop checkout not found at ${JUICE_SHOP_DIR}.${NC}"
  echo "  Set JUICE_SHOP_DIR to your checkout."
  exit 1
fi

FRONTEND_SRC="${JUICE_SHOP_DIR}/frontend/src"

echo -e "${BLUE}Applying RedSees Marketplace themepack to ${JUICE_SHOP_DIR}...${NC}"

# --- Fonts (self-hosted, no runtime CDN) ---
mkdir -p "${FRONTEND_SRC}/assets/public/fonts"
cp -f "${THEMEPACK}/fonts/"*.woff2 "${FRONTEND_SRC}/assets/public/fonts/"
echo "  fonts -> assets/public/fonts/"

# --- Logo + favicon ---
mkdir -p "${FRONTEND_SRC}/assets/public/images"
cp -f "${THEMEPACK}/images/RedSees_Logo.png" "${FRONTEND_SRC}/assets/public/images/"
cp -f "${THEMEPACK}/images/RedSees_Logo.svg" "${FRONTEND_SRC}/assets/public/images/"
cp -f "${THEMEPACK}/favicon/redsees_favicon.ico" "${FRONTEND_SRC}/assets/public/"
echo "  logo + favicon -> assets/public/"

# --- Product catalog images (custom icon set, referenced by config/redsees.yml) ---
mkdir -p "${FRONTEND_SRC}/assets/public/images/products"
cp -f "${THEMEPACK}/images/products/"*.png "${FRONTEND_SRC}/assets/public/images/products/"
echo "  product images -> assets/public/images/products/"

# --- App shell ---
cp -f "${THEMEPACK}/frontend-src/index.html" "${FRONTEND_SRC}/index.html"
echo "  index.html"

# --- Material theme + global styles ---
cp -f "${THEMEPACK}/frontend-src/styles.scss" "${FRONTEND_SRC}/styles.scss"
mkdir -p "${FRONTEND_SRC}/styles"
cp -f "${THEMEPACK}/frontend-src/styles/theme.scss" "${FRONTEND_SRC}/styles/theme.scss"
echo "  styles.scss + styles/theme.scss"

# --- Component-level restyles ---
cp -f "${THEMEPACK}/frontend-src/app/navbar/navbar.component.scss" "${FRONTEND_SRC}/app/navbar/navbar.component.scss"
cp -f "${THEMEPACK}/frontend-src/app/product/product.component.scss" "${FRONTEND_SRC}/app/product/product.component.scss"
cp -f "${THEMEPACK}/frontend-src/app/search-result/search-result.component.scss" "${FRONTEND_SRC}/app/search-result/search-result.component.scss"
cp -f "${THEMEPACK}/frontend-src/app/welcome-banner/welcome-banner.component.scss" "${FRONTEND_SRC}/app/welcome-banner/welcome-banner.component.scss"
echo "  navbar / product / search-result / welcome-banner component styles"

echo -e "${GREEN}✅ Themepack files applied.${NC}"

if [ "$SKIP_BUILD" = "true" ]; then
  echo -e "${YELLOW}SKIP_BUILD=true — skipping frontend rebuild. Re-skin will not be visible until built.${NC}"
  exit 0
fi

echo -e "${BLUE}Rebuilding frontend (npm run build:frontend)...${NC}"
(cd "$JUICE_SHOP_DIR" && npm run build:frontend)

echo -e "${GREEN}✅ Frontend rebuilt with the RedSees Marketplace re-skin.${NC}"
echo "  Start Juice Shop with NODE_CONFIG_ENV=redsees to apply matching branding/config."
echo "  (Juice Shop re-syncs its DB from config/redsees.yml's products list on every"
echo "   boot, so a plain restart — no manual DB reset — is enough to pick up a"
echo "   catalog change; the frontend rebuild above is only needed for new image files.)"

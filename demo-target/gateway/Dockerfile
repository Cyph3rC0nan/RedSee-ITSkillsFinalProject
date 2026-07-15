# RedSees Marketplace gateway — authorized lab target only.
# Reverse-proxies Juice Shop + the demo-target/ sink service behind one port.
# Run with --network host (see docker/demo-helper.sh's `marketplace` subcommand)
# so the port is never published through a Docker bridge/NAT mapping.
FROM node:22-slim

WORKDIR /app
COPY package.json .
RUN npm install --omit=dev

COPY gateway.js .

ENV GATEWAY_PORT=3000
EXPOSE 3000

CMD ["node", "gateway.js"]

# RedSees Marketplace companion sink service — authorized lab target only.
# Minimal, single-purpose image; run with --network host (see docker/demo-helper.sh's
# `marketplace` subcommand) so the port is never published through a Docker bridge/NAT.
FROM python:3.12-slim

WORKDIR /app
COPY marketplace_sinks.py .

RUN pip install --no-cache-dir flask

ENV MARKETPLACE_PORT=8081
EXPOSE 8081

CMD ["python", "marketplace_sinks.py"]

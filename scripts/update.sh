#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Pulling updates..."
git pull --ff-only

echo "Rebuilding..."
docker compose build --pull

echo "Restarting..."
docker compose up -d --remove-orphans

echo "Status:"
docker compose ps

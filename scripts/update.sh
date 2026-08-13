#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Pulling updates..."
git pull --ff-only

echo "Preparing persistent directories..."
mkdir -p logs data backups
if [ "$(id -u)" -eq 0 ]; then
  chown -R 10001:10001 logs data backups
elif command -v sudo >/dev/null 2>&1; then
  sudo chown -R 10001:10001 logs data backups
else
  echo "sudo is unavailable. Run: chown -R 10001:10001 logs data backups"
  exit 1
fi

echo "Rebuilding..."
docker compose build --pull

echo "Restarting..."
docker compose up -d --remove-orphans

echo "Status:"
docker compose ps

echo "Recent logs:"
docker compose logs --tail=30 discord-monitor

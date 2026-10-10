#!/bin/sh
# Brings the server up to the latest version on GitHub. Run on the server, from
# anywhere:  sh ~/shipbrace/deploy/update.sh
#
# Only fast-forward updates are taken, so a surprise rewrite of history on
# GitHub stops the update instead of being applied. The database and backups
# live in Docker volumes and are untouched by a rebuild.
set -eu
cd "$(dirname "$0")"
git pull --ff-only
docker compose up -d --build
docker image prune -f >/dev/null
docker compose ps

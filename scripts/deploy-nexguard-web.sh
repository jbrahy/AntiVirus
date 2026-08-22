#!/usr/bin/env bash
# Deploy avtool-web to pm-prod-development (nexguardhq.com).
#
# Run this ON the server (ssh ec2-user@10.30.1.94), not on a laptop --
# it needs sudo to restart the systemd unit. It replaces the old
# scp-a-tarball-of-the-binary-and-templates workflow: the server's
# /home/nexguardhq.com/repo is a real git checkout, so `git status`
# there always proves exactly which commit is running.
#
# Usage: ./deploy-nexguard-web.sh [ref]   (default ref: main)

set -euo pipefail
REF="${1:-main}"
REPO=/home/nexguardhq.com/repo

sudo -u nexguardhq.com bash -c "
  set -e
  cd '$REPO'
  git fetch origin
  git checkout '$REF'
  git merge --ff-only 'origin/$REF' 2>/dev/null || true
  GOTOOLCHAIN=auto HOME=/home/nexguardhq.com /usr/local/go/bin/go build -o bin/avtool-web ./cmd/avtool-web
"

sudo systemctl restart nexguard-web
sleep 1
sudo systemctl is-active nexguard-web

echo "--- deployed commit ---"
sudo -u nexguardhq.com bash -c "cd '$REPO' && git log --oneline -1"

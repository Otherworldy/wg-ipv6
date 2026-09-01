#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v go >/dev/null 2>&1; then
  echo "go not found; installing via apt..." >&2
  sudo apt-get update -qq && sudo apt-get install -y -qq golang-go 2>&1 | tail -2
fi
GOMAXPROCS=$(nproc) go mod tidy
go build -trimpath -ldflags "-s -w" -o bin/proxy-sticky .
echo "built: $(pwd)/bin/proxy-sticky"

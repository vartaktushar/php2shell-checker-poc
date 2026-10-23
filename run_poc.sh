#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab"
OUT="$ROOT/evidence"
mkdir -p "$OUT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi

capture() {
  local tag="$1"
  local label="$2"
  echo "Starting isolated lab with PHP $tag"
  PHP_TAG="$tag" docker compose -f "$LAB/docker-compose.yml" up -d --pull always
  local ready=0
  for _ in $(seq 1 45); do
    if curl --fail --silent http://127.0.0.1:18080/ >/dev/null; then ready=1; break; fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    PHP_TAG="$tag" docker compose -f "$LAB/docker-compose.yml" logs --no-color > "$OUT/${label}-docker.log" || true
    echo "Lab did not become ready; see $OUT/${label}-docker.log" >&2
    exit 1
  fi
  {
    echo "PHP2Shell non-destructive checker — $label image ($tag)"
    echo "$ docker compose image and endpoint"
    PHP_TAG="$tag" docker compose -f "$LAB/docker-compose.yml" ps
    echo
    echo "$ curl -sSI http://127.0.0.1:18080/"
    curl --silent --show-error --head http://127.0.0.1:18080/
    echo
    echo "$ python3 php2shell_check.py http://127.0.0.1:18080/"
    python3 "$ROOT/php2shell_check.py" http://127.0.0.1:18080/
  } | tee "$OUT/${label}-run.txt"
  # Save the actual endpoint response separately to make its PHP fingerprint
  # and version easy to inspect without the UI capture.
  curl --silent --show-error --dump-header "$OUT/${label}-headers.txt" http://127.0.0.1:18080/ > "$OUT/${label}-response.txt"
  PHP_TAG="$tag" docker compose -f "$LAB/docker-compose.yml" down --remove-orphans
}

capture "8.5.11" "vulnerable"
PHP_TAG="8.5.12" docker compose -f "$LAB/docker-compose.yml" up -d --pull always
for _ in $(seq 1 45); do
  if curl --fail --silent http://127.0.0.1:18080/ >/dev/null; then break; fi
  sleep 1
done
{
  echo "PHP2Shell non-destructive checker — patched image (8.5.12)"
  echo "$ docker compose image and endpoint"
  PHP_TAG="8.5.12" docker compose -f "$LAB/docker-compose.yml" ps
  echo
  echo "$ curl -sSI http://127.0.0.1:18080/"
  curl --silent --show-error --head http://127.0.0.1:18080/
  echo
  echo "$ python3 php2shell_check.py http://127.0.0.1:18080/"
  python3 "$ROOT/php2shell_check.py" http://127.0.0.1:18080/
} | tee "$OUT/patched-run.txt"
curl --silent --show-error --dump-header "$OUT/patched-headers.txt" http://127.0.0.1:18080/ > "$OUT/patched-response.txt"
PHP_TAG="8.5.12" docker compose -f "$LAB/docker-compose.yml" down --remove-orphans

# Keep a combined text transcript. Capture screenshots directly from iTerm
# after running the checker there; this script does not capture the desktop.
{
  cat "$OUT/vulnerable-run.txt"
  echo
  echo "============================================================"
  echo
  cat "$OUT/patched-run.txt"
} > "$OUT/end-to-end.txt"
echo "Saved run transcripts and response evidence in: $OUT"
echo "No screenshots were captured. Use iTerm's window screenshot shortcut for your post."

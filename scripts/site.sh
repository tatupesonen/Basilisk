#!/usr/bin/env bash
# basilisk's website and documentation, built only in a container
# (ADR-030, ADR-031; docs/features/site.md). Node.js is never installed on
# the host: every step below runs in the image defined by
# site/container/Dockerfile, with the repository mounted at /repo.
#
#   scripts/site.sh build     build the static site into site/dist/
#   scripts/site.sh serve     build, then preview on http://127.0.0.1:4321/
#                             (stops by itself after SITE_SERVE_MINUTES, default 30)
#   scripts/site.sh check     build at / and under /basilisk/, check links,
#                             external requests and diagrams
#   scripts/site.sh shoot     screenshots of site/dist into docs/features/site-screenshots/
#                             (SHOOT_OUT=<dir relative to site/> and --review for the long set)
#   scripts/site.sh dep-age   check every package in the lock file is >= 14 days old (network)
#   scripts/site.sh lock      regenerate site/package-lock.json from package.json,
#                             resolving only versions published before SITE_DEPS_BEFORE
#                             (default: 15 days ago)
#   scripts/site.sh shell     a shell in the image, for debugging
#
# Environment: SITE_BASE (base path, default /), SITE_URL (canonical origin),
# SITE_TIMEOUT (seconds per container, default 1200).
#
# The image: site/container/Dockerfile starts FROM the Playwright image pinned
# by digest; its header says how to move that digest. This script tags the
# built image bk-site/build:<hash of the Dockerfile>, so a changed Dockerfile
# is rebuilt automatically and an unchanged one is reused.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(pwd)

cmd=${1:-}
[ -n "$cmd" ] || { sed -n '2,24p' "$0"; exit 2; }
shift || true

limit=${SITE_TIMEOUT:-1200}
dockerfile=site/container/Dockerfile
if command -v sha256sum >/dev/null 2>&1; then
  hash=$(sha256sum "$dockerfile" | cut -c1-12)
else
  hash=$(shasum -a 256 "$dockerfile" | cut -c1-12)
fi
image="bk-site/build:$hash"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "site: building image $image"
  docker build --pull=false -t "$image" -f "$dockerfile" site/container
fi

name="bk-site-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

tty=()
[ -t 0 ] && [ -t 1 ] && tty=(-it)

# run <seconds> <extra docker args...> -- <shell script>
run() {
  local secs=$1; shift
  local args=()
  while [ "$1" != "--" ]; do args+=("$1"); shift; done
  shift
  docker run --rm --init --name "$name" ${tty[@]+"${tty[@]}"} \
    --cpus 3 --memory 6g --shm-size 1g \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/home \
    -e npm_config_cache=/repo/site/.cache/npm \
    -e SITE_BASE="${SITE_BASE:-/}" \
    -e SITE_URL="${SITE_URL:-}" \
    -e SITE_REPO="${SITE_REPO:-}" \
    -e SITE_DEPS_BEFORE="${SITE_DEPS_BEFORE:-}" \
    -e CI="${CI:-}" \
    -v "$repo:/repo" -w /repo/site \
    ${args[@]+"${args[@]}"} "$image" \
    timeout --kill-after=15 "$secs" bash -euo pipefail -c "$1"
}

# Install node_modules from the lock file when missing or out of date.
deps='
lock_sha=$(sha256sum package-lock.json | cut -c1-16)
if [ "$(cat node_modules/.bk-lock-sha 2>/dev/null)" != "$lock_sha" ]; then
  echo "site: npm ci"
  npm ci --no-audit --no-fund --loglevel=error
  echo "$lock_sha" > node_modules/.bk-lock-sha
fi
'
build='scripts/prepare.sh && npx astro build --silent'

case "$cmd" in
  build)
    run "$limit" -- "$deps $build"
    echo "site: built site/dist/ (base ${SITE_BASE:-/})"
    ;;
  serve)
    mins=${SITE_SERVE_MINUTES:-30}
    echo "site: preview on http://127.0.0.1:4321/ for at most $mins minutes (Ctrl+C stops it)"
    run $((mins * 60)) -p 127.0.0.1:4321:4321 -- \
      "$deps $build && npx astro preview --host 0.0.0.0 --port 4321"
    ;;
  check)
    run "$limit" -- "$deps
      echo 'site: build under /basilisk/'
      SITE_BASE=/basilisk/ SITE_OUT=.cache/dist-subpath $build
      node scripts/check-site.mjs .cache/dist-subpath /basilisk/
      echo 'site: build at /'
      SITE_BASE=/ $build
      node scripts/check-site.mjs dist /"
    echo "site: check passed"
    ;;
  shoot)
    [ -d site/dist ] || { echo "site: run scripts/site.sh build first" >&2; exit 1; }
    run "$limit" -- "$deps node scripts/shoot.mjs dist ${SHOOT_OUT:-../docs/features/site-screenshots} $*"
    ;;
  dep-age)
    run "$limit" -- "$deps node scripts/check-dep-age.mjs"
    ;;
  lock)
    run "$limit" -- '
      before=${SITE_DEPS_BEFORE:-$(date -u -d "15 days ago" +%Y-%m-%dT00:00:00Z)}
      echo "site: resolving versions published before $before"
      rm -rf node_modules
      npm install --before="$before" --save-exact --no-audit --no-fund --loglevel=error
      lock_sha=$(sha256sum package-lock.json | cut -c1-16)
      echo "$lock_sha" > node_modules/.bk-lock-sha'
    ;;
  shell)
    run "$limit" -- 'bash'
    ;;
  *)
    echo "site: unknown command $cmd" >&2
    exit 2
    ;;
esac

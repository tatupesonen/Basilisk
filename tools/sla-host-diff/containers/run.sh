#!/bin/sh
# Runs build-sleigh.sh in a container, bounded and removed afterwards.
#
#   run.sh IMAGE PLATFORM NAME CXX "EXTRA" SECONDS [SETUP] [-- SPEC...]
#
# IMAGE     image id or a tag of this track's (never retag shared images)
# PLATFORM  linux/arm64 or linux/amd64
# SETUP     shell commands run first as root (e.g. apt-get install ...)
# WORK (env) the work directory (default target/sla-host-diff/work of the
#           worktree); mounted at /work.
set -eu
IMAGE=$1; PLATFORM=$2; NAME=$3; CXXCMD=$4; EXTRA=$5; SECONDS_=$6; shift 6
SETUP=${1:-true}; [ $# -gt 0 ] && shift
[ "${1:-}" = "--" ] && shift
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$HERE/../../../target/sla-host-diff/work}
WORK=$(cd "$WORK" && pwd)
cp "$HERE/build-sleigh.sh" "$WORK/build-sleigh.sh"
CNAME=sla-host-diff-$NAME
docker rm -f "$CNAME" > /dev/null 2>&1 || true
# The container kills itself after SECONDS; `docker run --rm` removes it.
docker run --rm --name "$CNAME" --platform "$PLATFORM" --cpus 3 \
  -v "$WORK:/work" "$IMAGE" \
  sh -c "( sleep $SECONDS_; kill -9 -1 ) & $SETUP && sh /work/build-sleigh.sh /work '$NAME' '$CXXCMD' '$EXTRA' $*"

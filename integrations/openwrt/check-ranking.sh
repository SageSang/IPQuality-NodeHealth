#!/bin/sh
# Existing entry point; both modes share one lock and commit selector.
set -u
ENV_FILE="${NODE_HEALTH_ENV_FILE:-/etc/local-socks/node-health.env}"
[ -r "$ENV_FILE" ] || { echo 'node-health environment file is not readable' >&2; exit 1; }
set -a
. "$ENV_FILE"
set +a
: "${NODE_BIN:=/usr/bin/node}"
: "${NODE_PATH:=/etc/local-socks/node_modules:/usr/lib/node_modules}"
: "${RUNTIME_CONTROLLER:=$(dirname "$0")/runtime-controller.mjs}"
export NODE_PATH
umask 077
: "${WORK_DIR:=/etc/local-socks}"
: "${CACHE_DIR:=$WORK_DIR/cache/node-health}"
: "${FLOCK_BIN:=flock}"
command -v "$FLOCK_BIN" >/dev/null 2>&1 || { echo 'node-health: flock unavailable' >&2; exit 1; }
command -v "$NODE_BIN" >/dev/null 2>&1 || { echo 'node-health: node unavailable' >&2; exit 1; }
[ -r "$RUNTIME_CONTROLLER" ] || { echo 'node-health: controller unavailable' >&2; exit 1; }
mkdir -p "$CACHE_DIR" || exit 1
exec 9>"$CACHE_DIR/apply.lock"
"$FLOCK_BIN" -n 9 2>/dev/null || exit 75
export NODE_HEALTH_LOCK_FD=9
exec "$NODE_BIN" "$RUNTIME_CONTROLLER" check

#!/bin/sh
# Root-owned forced-command worker; shares the existing scheduled refresh lock.
set -eu
umask 077
set -a
. /etc/local-socks/node-health.env
set +a
export NODE_PATH="${NODE_PATH:-/etc/local-socks/node_modules:/usr/lib/node_modules}"
exec 9> /etc/local-socks/cache/node-health/apply.lock
if ! flock -n 9; then
  exec /usr/bin/node /etc/sidora-network/cli.mjs --busy "$1"
fi
# Serialize against a native OpenClash update as well. Never unlink either lock.
exec 8> /tmp/lock/openclash_subs.lock
if ! flock -n 8; then
  exec /usr/bin/node /etc/sidora-network/cli.mjs --busy "$1"
fi
exec /usr/bin/node /etc/sidora-network/cli.mjs --worker "$1"

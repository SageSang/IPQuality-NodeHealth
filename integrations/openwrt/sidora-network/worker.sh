#!/bin/bash
# Invoked only by the root-owned tool after a durable operation receipt is created.
set -eu
umask 077
exec 9> /tmp/lock/openclash_subs.lock
if ! flock -n 9; then
  exec /usr/bin/node /etc/sidora-network/cli.mjs --busy "$1"
fi
# Never unlink the original lock. fd 9 is inherited and checked before replacement.
exec /usr/bin/node /etc/sidora-network/cli.mjs --worker "$1"

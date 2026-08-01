#!/bin/sh
# procd service implementation for the independent local-socks Mihomo runtime.

BASE='/etc/local-socks'
ENV_FILE="${NODE_HEALTH_ENV_FILE:-$BASE/node-health.env}"

if [ -r "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

: "${MIHOMO_SOURCE:=/etc/openclash/core/clash_meta}"
: "${MIHOMO_BIN:=$BASE/bin/mihomo-local-socks}"
: "${CONFIG_PATH:=$BASE/config.yaml}"
: "${LOCAL_SOCKS_USER:=nobody}"
: "${LOCAL_SOCKS_NOFILE:=65535 65535}"

prepare_runtime_binary() {
  [ -x "$MIHOMO_SOURCE" ] || {
    logger -t local-socks "Mihomo source is unavailable: $MIHOMO_SOURCE"
    return 1
  }

  runtime_dir="$(dirname "$MIHOMO_BIN")"
  mkdir -p "$runtime_dir" || return 1
  if [ -x "$MIHOMO_BIN" ] && cmp -s "$MIHOMO_SOURCE" "$MIHOMO_BIN"; then
    return 0
  fi

  runtime_tmp="$MIHOMO_BIN.new.$$"
  rm -f -- "$runtime_tmp"
  cp "$MIHOMO_SOURCE" "$runtime_tmp" || return 1
  chown root:root "$runtime_tmp" || {
    rm -f -- "$runtime_tmp"
    return 1
  }
  chmod 0755 "$runtime_tmp" || {
    rm -f -- "$runtime_tmp"
    return 1
  }
  mv -f "$runtime_tmp" "$MIHOMO_BIN"
}

start_service() {
  [ -s "$CONFIG_PATH" ] || {
    logger -t local-socks 'config.yaml is missing; run check-ranking.sh first'
    return 1
  }
  prepare_runtime_binary || return 1

  procd_open_instance
  procd_set_param command "$MIHOMO_BIN" -d "$BASE" -f "$CONFIG_PATH"
  procd_set_param user "$LOCAL_SOCKS_USER"
  procd_set_param limits nofile="$LOCAL_SOCKS_NOFILE"
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}

#!/bin/sh
# Apply a coherent inventory/ranking pair to local-socks with validation and rollback.

set -u

if [ "$#" -ne 3 ]; then
  echo "usage: $0 INVENTORY_YAML CURRENT_JSON VERSION" >&2
  exit 2
fi

SOURCE_YAML="$1"
CURRENT_JSON="$2"
EXPECTED_VERSION="$3"
ENV_FILE="${NODE_HEALTH_ENV_FILE:-/etc/local-socks/node-health.env}"
STABLE_CONVERTER_OVERRIDE="${STABLE_CONVERTER_OVERRIDE:-}"

if [ ! -r "$ENV_FILE" ]; then
  echo 'node-health environment file is not readable' >&2
  exit 1
fi

# shellcheck disable=SC1090
. "$ENV_FILE"

: "${WORK_DIR:=/etc/local-socks}"
: "${CACHE_DIR:=$WORK_DIR/cache/node-health}"
: "${CONVERT_RUNNER:=$WORK_DIR/convert-ranking.mjs}"
: "${STABLE_CONVERTER:=$WORK_DIR/convert-any-proxy-to-local-socks-stable.js}"
: "${NODE_BIN:=/usr/bin/node}"
: "${NODE_PATH:=/etc/local-socks/node_modules:/usr/lib/node_modules}"
: "${JS_YAML_PATH:=}"
: "${MIHOMO_BIN:=/etc/openclash/core/clash_meta}"
: "${SERVICE_SCRIPT:=/etc/init.d/local-socks}"
: "${CONFIG_PATH:=$WORK_DIR/config.yaml}"
: "${START_PORT:=62000}"
: "${CONFIG_OWNER:=root:nogroup}"
: "${CONFIG_MODE:=0640}"
: "${EXPORT_DIR:=/root/local-socks}"
: "${ADVERTISE_HOST:=192.0.2.4}"
: "${READINESS_ATTEMPTS:=5}"
: "${READINESS_DELAY_SECONDS:=2}"
: "${LISTENER_CONNECT_TIMEOUT_MS:=1500}"
: "${LISTENER_CHECK_CONCURRENCY:=64}"

if [ -n "$STABLE_CONVERTER_OVERRIDE" ]; then
  STABLE_CONVERTER="$STABLE_CONVERTER_OVERRIDE"
fi

export NODE_PATH JS_YAML_PATH CONFIG_PATH WORK_DIR CACHE_DIR

CANDIDATE=''
BACKUP=''
EXPORT_STAGE=''
EXPORT_BACKUP=''
REPLACED=0

cleanup() {
  if [ -n "$CANDIDATE" ] && [ -f "$CANDIDATE" ]; then
    rm -f -- "$CANDIDATE"
  fi
  if [ -n "$EXPORT_STAGE" ] && [ -d "$EXPORT_STAGE" ]; then
    rm -rf -- "$EXPORT_STAGE"
  fi
  if [ -n "$EXPORT_BACKUP" ] && [ -e "$EXPORT_BACKUP" ] && [ ! -e "$EXPORT_DIR" ]; then
    if mv "$EXPORT_BACKUP" "$EXPORT_DIR" 2>/dev/null; then
      EXPORT_BACKUP=''
    else
      echo "apply-ranking: warning: TXT export backup remains at $EXPORT_BACKUP" >&2
    fi
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

fail() {
  echo "apply-ranking: $*" >&2
  exit 1
}

if [ "$START_PORT" != '62000' ]; then
  fail 'START_PORT must be exactly 62000 for the fixed regional port plan'
fi

for readable in "$SOURCE_YAML" "$CURRENT_JSON" "$CONVERT_RUNNER" "$STABLE_CONVERTER"; do
  [ -r "$readable" ] || fail "required file is not readable: $readable"
done
for executable in "$NODE_BIN" "$MIHOMO_BIN" "$SERVICE_SCRIPT"; do
  [ -x "$executable" ] || fail "required command is not executable: $executable"
done

mkdir -p "$WORK_DIR" "$CACHE_DIR" || fail 'cannot prepare working directories'
case "$EXPORT_DIR" in
  ''|'/') fail 'EXPORT_DIR must be a dedicated directory' ;;
esac
mkdir -p "$(dirname "$EXPORT_DIR")" || fail 'cannot prepare export parent directory'

case "$CONFIG_PATH" in
  "$EXPORT_DIR"|"$EXPORT_DIR"/*) fail 'CONFIG_PATH must not be inside EXPORT_DIR' ;;
esac

actual_version="$($NODE_BIN -e 'const fs=require("fs");const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(value.schema_version!==1||typeof value.version!=="string"||!value.version)process.exit(2);process.stdout.write(value.version);' "$CURRENT_JSON")" \
  || fail 'current.json is invalid'
if [ "$actual_version" != "$EXPECTED_VERSION" ]; then
  fail 'current.json version does not match poller version'
fi

CANDIDATE="$(mktemp "$WORK_DIR/.config.candidate.XXXXXX")" || fail 'cannot create candidate config'
EXPORT_STAGE="$(mktemp -d "${EXPORT_DIR}.new.XXXXXX")" || fail 'cannot create TXT export staging directory'
if ! "$NODE_BIN" "$CONVERT_RUNNER" \
  "$SOURCE_YAML" \
  "$CURRENT_JSON" \
  "$CANDIDATE" \
  "$START_PORT" \
  "$STABLE_CONVERTER" \
  "$EXPORT_STAGE" \
  "$ADVERTISE_HOST"; then
  fail 'conversion failed'
fi

chmod "$CONFIG_MODE" "$CANDIDATE" || fail 'cannot protect candidate config'
if [ -n "$CONFIG_OWNER" ]; then
  chown "$CONFIG_OWNER" "$CANDIDATE" || fail 'cannot set candidate owner'
fi

if ! "$MIHOMO_BIN" -d "$WORK_DIR" -t -f "$CANDIDATE" >/dev/null 2>&1; then
  fail 'Mihomo rejected candidate config'
fi

if [ -f "$CONFIG_PATH" ]; then
  BACKUP="$(mktemp "$CACHE_DIR/config.previous.XXXXXX")" || fail 'cannot create rollback copy'
  cp -p "$CONFIG_PATH" "$BACKUP" || fail 'cannot copy rollback config'
  chmod 600 "$BACKUP" || fail 'cannot protect rollback config'
fi

mv -f "$CANDIDATE" "$CONFIG_PATH" || fail 'atomic config replacement failed'
CANDIDATE=''
REPLACED=1

service_ready() {
  attempts=0
  while [ "$attempts" -lt "$READINESS_ATTEMPTS" ]; do
    sleep "$READINESS_DELAY_SECONDS"
    if "$SERVICE_SCRIPT" status >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
  done
  return 1
}

listeners_ready() {
  attempts=0
  while [ "$attempts" -lt "$READINESS_ATTEMPTS" ]; do
    if "$NODE_BIN" - "$CONFIG_PATH" "$LISTENER_CONNECT_TIMEOUT_MS" "$LISTENER_CHECK_CONCURRENCY" <<'NODE'
const fs = require('fs');
const net = require('net');
const path = require('path');

const configPath = process.argv[2];
const timeoutMs = Number(process.argv[3]);
const concurrency = Number(process.argv[4]);
const yaml = process.env.JS_YAML_PATH
  ? require(path.resolve(process.env.JS_YAML_PATH))
  : require('js-yaml');
const config = yaml.load(fs.readFileSync(configPath, 'utf8'));
if (!config || !Array.isArray(config.listeners)) {
  throw new Error('applied config has no listeners array');
}
if (!Number.isInteger(timeoutMs) || timeoutMs < 100) {
  throw new Error('LISTENER_CONNECT_TIMEOUT_MS must be an integer >= 100');
}
if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 512) {
  throw new Error('LISTENER_CHECK_CONCURRENCY must be an integer in 1..512');
}

const ports = [];
const seen = new Set();
for (const listener of config.listeners) {
  const port = Number(listener && listener.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid listener port: ${listener && listener.port}`);
  }
  if (!seen.has(port)) {
    seen.add(port);
    ports.push(port);
  }
}

function connect(port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(error || '');
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(''));
    socket.once('timeout', () => finish('timeout'));
    socket.once('error', (error) => finish(error.code || error.message));
  });
}

(async () => {
  let cursor = 0;
  const failures = [];
  async function worker() {
    while (cursor < ports.length) {
      const port = ports[cursor];
      cursor += 1;
      const error = await connect(port);
      if (error) failures.push(`${port}:${error}`);
    }
  }
  const workers = Array.from(
    { length: Math.min(concurrency, ports.length) },
    () => worker(),
  );
  await Promise.all(workers);
  if (failures.length > 0) {
    throw new Error(`listeners not reachable: ${failures.slice(0, 20).join(', ')}`);
  }
})().catch((error) => {
  process.stderr.write(`apply-ranking: ${error.message}\n`);
  process.exitCode = 1;
});
NODE
    then
      return 0
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -lt "$READINESS_ATTEMPTS" ]; then
      sleep "$READINESS_DELAY_SECONDS"
    fi
  done
  return 1
}

rollback() {
  restore_ok=1
  cp -p "$CONFIG_PATH" "$CACHE_DIR/failed-config.yaml" 2>/dev/null || true
  chmod 600 "$CACHE_DIR/failed-config.yaml" 2>/dev/null || true

  if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
    restore="$(mktemp "$WORK_DIR/.config.restore.XXXXXX")" || restore_ok=0
    if [ "$restore_ok" -eq 1 ] && ! cp -p "$BACKUP" "$restore"; then
      rm -f -- "$restore"
      restore_ok=0
    fi
    if [ "$restore_ok" -eq 1 ] && ! chmod "$CONFIG_MODE" "$restore"; then
      rm -f -- "$restore"
      restore_ok=0
    fi
    if [ "$restore_ok" -eq 1 ] && [ -n "$CONFIG_OWNER" ] && ! chown "$CONFIG_OWNER" "$restore"; then
      rm -f -- "$restore"
      restore_ok=0
    fi
    if [ "$restore_ok" -eq 1 ] && ! mv -f "$restore" "$CONFIG_PATH"; then
      rm -f -- "$restore"
      restore_ok=0
    fi
    if [ "$restore_ok" -eq 1 ]; then
      if mv -f "$BACKUP" "$CACHE_DIR/config.previous.yaml"; then
        BACKUP=''
        chmod 600 "$CACHE_DIR/config.previous.yaml" 2>/dev/null || true
      else
        echo "apply-ranking: warning: rollback copy remains at $BACKUP" >&2
      fi
    fi
  elif [ "$REPLACED" -eq 1 ]; then
    rm -f -- "$CONFIG_PATH" || restore_ok=0
  fi

  [ "$restore_ok" -eq 1 ] || return 1
  if ! "$SERVICE_SCRIPT" restart >/dev/null 2>&1; then
    return 1
  fi
  service_ready
}

fail_after_rollback() {
  reason="$1"
  if rollback; then
    fail "$reason; previous config restored and ready"
  fi
  fail "$reason; rollback failed, manual recovery is required"
}

publish_exports() {
  if [ -e "$EXPORT_DIR" ]; then
    EXPORT_BACKUP="${EXPORT_DIR}.previous.$$"
    [ ! -e "$EXPORT_BACKUP" ] || return 1
    mv "$EXPORT_DIR" "$EXPORT_BACKUP" || return 1
  fi

  if mv "$EXPORT_STAGE" "$EXPORT_DIR"; then
    EXPORT_STAGE=''
    if [ -n "$EXPORT_BACKUP" ] && [ -d "$EXPORT_BACKUP" ]; then
      if ! rm -rf -- "$EXPORT_BACKUP"; then
        echo "apply-ranking: warning: old TXT export remains at $EXPORT_BACKUP" >&2
      fi
      EXPORT_BACKUP=''
    fi
    return 0
  fi

  if [ -n "$EXPORT_BACKUP" ] && [ -d "$EXPORT_BACKUP" ]; then
    if mv "$EXPORT_BACKUP" "$EXPORT_DIR" 2>/dev/null; then
      EXPORT_BACKUP=''
    fi
  fi
  return 1
}

if ! "$SERVICE_SCRIPT" restart >/dev/null 2>&1; then
  fail_after_rollback 'service restart failed'
fi
if ! service_ready; then
  fail_after_rollback 'service readiness failed'
fi
if ! listeners_ready; then
  fail_after_rollback 'one or more configured listeners are not reachable'
fi
if ! publish_exports; then
  fail_after_rollback 'TXT export publish failed'
fi

if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
  if mv -f "$BACKUP" "$CACHE_DIR/config.previous.yaml"; then
    BACKUP=''
    chmod 600 "$CACHE_DIR/config.previous.yaml" 2>/dev/null || true
  else
    echo "apply-ranking: warning: previous config remains at $BACKUP" >&2
    BACKUP=''
  fi
fi

exit 0

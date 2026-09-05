#!/bin/sh
# Poll node-health and atomically apply a coherent inventory/ranking pair.
# Intended for OpenWrt/BusyBox ash every ten minutes.

set -u

ENV_FILE="${NODE_HEALTH_ENV_FILE:-/etc/local-socks/node-health.env}"
if [ ! -r "$ENV_FILE" ]; then
  logger -t node-health-ranking "configuration is not readable"
  exit 1
fi

# shellcheck disable=SC1090
. "$ENV_FILE"

: "${RANKING_URL:?RANKING_URL is required}"
: "${SOURCE_URL:?SOURCE_URL is required}"
: "${WORK_DIR:=/etc/local-socks}"
: "${CACHE_DIR:=$WORK_DIR/cache/node-health}"
: "${APPLY_COMMAND:=$WORK_DIR/apply-ranking.sh}"
: "${STABLE_CONVERTER_URL:=}"
: "${NODE_BIN:=/usr/bin/node}"
: "${NODE_PATH:=/etc/local-socks/node_modules:/usr/lib/node_modules}"
: "${JS_YAML_PATH:=}"
: "${SERVICE_SCRIPT:=/etc/init.d/local-socks}"
: "${SERVICE_NAME:=local-socks}"
: "${CONFIG_PATH:=$WORK_DIR/config.yaml}"
: "${EXPORT_DIR:=/root/local-socks}"
: "${SHA256_BIN:=sha256sum}"
: "${CURL_CONNECT_TIMEOUT:=10}"
: "${CURL_MAX_TIME:=120}"
: "${BACKOFF_BASE_SECONDS:=900}"
: "${BACKOFF_MAX_SECONDS:=21600}"
: "${READINESS_ATTEMPTS:=5}"
: "${READINESS_DELAY_SECONDS:=2}"
: "${LISTENER_CONNECT_TIMEOUT_MS:=1500}"
: "${LISTENER_CHECK_CONCURRENCY:=64}"

export NODE_PATH JS_YAML_PATH

LOCK_FILE="$CACHE_DIR/check-ranking.lock"
LOCK_DIR='/tmp/node-health-check-ranking.lock.d'
LOCK_OWNER_FILE="$LOCK_DIR/owner"
APPLIED_VERSION_FILE="$CACHE_DIR/applied.version"
APPLIED_CHECKSUM_FILE="$CACHE_DIR/applied.sha256"
BACKOFF_FILE="$CACHE_DIR/backoff.state"
STAGE_DIR=''
LOCK_STYLE=''

log() {
  logger -t node-health-ranking "$*"
}

cleanup() {
  if [ -n "$STAGE_DIR" ] && [ -d "$STAGE_DIR" ]; then
    rm -rf -- "$STAGE_DIR"
  fi
  if [ "$LOCK_STYLE" = 'mkdir' ] && [ -d "$LOCK_DIR" ]; then
    rm -rf -- "$LOCK_DIR"
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir -p "$CACHE_DIR" || exit 1

if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    exit 0
  fi
  LOCK_STYLE='flock'
else
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    # Give the owner time to write its identity before deciding the lock is
    # stale. /proc start ticks prevent PID reuse from preserving a dead lock.
    sleep 1
    lock_pid=''
    lock_start=''
    if [ -r "$LOCK_OWNER_FILE" ]; then
      read -r lock_pid lock_start < "$LOCK_OWNER_FILE" || true
    fi
    current_start=''
    case "${lock_pid:-}:${lock_start:-}" in
      *[!0-9:]*|:|*:) ;;
      *)
        if [ -r "/proc/$lock_pid/stat" ]; then
          current_start="$(awk '{print $22}' "/proc/$lock_pid/stat" 2>/dev/null)"
        fi
        ;;
    esac
    if [ -n "$current_start" ] && [ "$current_start" = "$lock_start" ]; then
      exit 0
    fi
    log 'removing stale fallback lock'
    rm -rf -- "$LOCK_DIR" || exit 1
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
      exit 0
    fi
  fi
  LOCK_STYLE='mkdir'
  process_start="$(awk '{print $22}' "/proc/$$/stat" 2>/dev/null)"
  case "${process_start:-}" in
    *[!0-9]*|'')
      log 'cannot record fallback lock owner'
      exit 1
      ;;
  esac
  printf '%s %s\n' "$$" "$process_start" > "$LOCK_OWNER_FILE" || exit 1
fi


record_failure() {
  reason="$1"
  attempts=0
  if [ -s "$BACKOFF_FILE" ]; then
    read -r _retry_after attempts < "$BACKOFF_FILE" || true
  fi
  case "${attempts:-}" in
    *[!0-9]*|'') attempts=0 ;;
  esac
  attempts=$((attempts + 1))

  delay="$BACKOFF_BASE_SECONDS"
  count=1
  while [ "$count" -lt "$attempts" ] && [ "$delay" -lt "$BACKOFF_MAX_SECONDS" ]; do
    delay=$((delay * 2))
    if [ "$delay" -gt "$BACKOFF_MAX_SECONDS" ]; then
      delay="$BACKOFF_MAX_SECONDS"
    fi
    count=$((count + 1))
  done

  retry_after=$(($(date +%s) + delay))
  printf '%s %s\n' "$retry_after" "$attempts" > "$BACKOFF_FILE.tmp"
  mv -f "$BACKOFF_FILE.tmp" "$BACKOFF_FILE"
  log "$reason; retry delayed ${delay}s (attempt ${attempts})"
  exit 1
}

sha256_file() {
  checksum_output="$("$SHA256_BIN" "$1" 2>/dev/null)" || return 1
  set -- $checksum_output
  checksum="${1:-}"
  if [ "${#checksum}" -ne 64 ]; then
    return 1
  fi
  case "$checksum" in
    *[!0-9a-fA-F]*) return 1 ;;
  esac
  printf '%s' "$checksum" | tr 'A-F' 'a-f'
}

service_running() {
  if command -v ubus >/dev/null 2>&1 && command -v jsonfilter >/dev/null 2>&1; then
    running="$(
      ubus call service list "{\"name\":\"$SERVICE_NAME\"}" 2>/dev/null \
        | jsonfilter -e '@.*.instances.*.running' 2>/dev/null
    )"
    [ "$running" = 'true' ]
    return
  fi
  "$SERVICE_SCRIPT" status >/dev/null 2>&1
}

first_listener_ready() {
  [ -r "$CONFIG_PATH" ] || return 1
  "$NODE_BIN" - "$CONFIG_PATH" "$LISTENER_CONNECT_TIMEOUT_MS" <<'NODE'
const fs = require('fs');
const net = require('net');
const path = require('path');

const configPath = process.argv[2];
const timeoutMs = Number(process.argv[3]);
const yaml = process.env.JS_YAML_PATH
  ? require(path.resolve(process.env.JS_YAML_PATH))
  : require('js-yaml');
const config = yaml.load(fs.readFileSync(configPath, 'utf8'));
const listener = config && Array.isArray(config.listeners) ? config.listeners[0] : null;
const port = Number(listener && listener.port);
if (!Number.isInteger(port) || port < 1 || port > 65535) process.exit(2);

const socket = net.createConnection({ host: '127.0.0.1', port });
let settled = false;
function finish(code) {
  if (settled) return;
  settled = true;
  socket.destroy();
  process.exitCode = code;
}
socket.setTimeout(timeoutMs);
socket.once('connect', () => finish(0));
socket.once('timeout', () => finish(1));
socket.once('error', () => finish(1));
NODE
}

runtime_ready() {
  service_running && all_listeners_ready
}

all_listeners_ready() {
  [ -r "$CONFIG_PATH" ] || return 1
  "$NODE_BIN" - "$CONFIG_PATH" "$LISTENER_CONNECT_TIMEOUT_MS" "$LISTENER_CHECK_CONCURRENCY" <<'NODE'
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
if (!config || !Array.isArray(config.listeners)) process.exit(2);
if (config.listeners.length === 0) process.exit(0);
if (!Number.isInteger(timeoutMs) || timeoutMs < 100) process.exit(2);
if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 512) process.exit(2);

const ports = [...new Set(config.listeners.map((listener) => Number(listener && listener.port)))];
if (ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) process.exit(2);

function connect(port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

(async () => {
  let cursor = 0;
  let failed = false;
  async function worker() {
    while (cursor < ports.length) {
      const port = ports[cursor++];
      if (!(await connect(port))) failed = true;
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, ports.length) }, () => worker()),
  );
  process.exitCode = failed ? 1 : 0;
})().catch(() => {
  process.exitCode = 1;
});
NODE
}

stable_ports_match_ranking() {
  ranking_path="$1"
  [ -r "$CONFIG_PATH" ] || return 1
  [ -r "$ranking_path" ] || return 1
  "$NODE_BIN" - "$CONFIG_PATH" "$ranking_path" "$START_PORT" <<'NODE'
const fs = require('fs');
const path = require('path');

const configPath = process.argv[2];
const rankingPath = process.argv[3];
const startPort = Number(process.argv[4]);
const yaml = process.env.JS_YAML_PATH
  ? require(path.resolve(process.env.JS_YAML_PATH))
  : require('js-yaml');
const config = yaml.load(fs.readFileSync(configPath, 'utf8'));
const ranking = JSON.parse(fs.readFileSync(rankingPath, 'utf8'));
const regionOrder = [
  'hong-kong', 'taiwan', 'japan', 'singapore', 'united-states',
  'south-korea', 'united-kingdom', 'germany', 'france', 'canada',
  'australia', 'other',
];
const ports = new Set(
  (config && Array.isArray(config.listeners) ? config.listeners : [])
    .map((listener) => Number(listener && listener.port)),
);
const missing = [];
for (const [region, payload] of Object.entries(ranking.regions || {})) {
  const regionIndex = regionOrder.indexOf(region);
  if (regionIndex < 0 || region === 'other') continue;
  const slots = payload && (payload.stable_slots || payload.stableSlots);
  if (!slots || typeof slots !== 'object' || Array.isArray(slots)) {
    process.exit(1);
  }
  for (const slot of Object.keys(slots)) {
    const slotNumber = Number(slot);
    if (!Number.isInteger(slotNumber) || slotNumber < 1 || slotNumber > 3) process.exit(1);
    const expected = startPort + regionIndex * 200 + slotNumber - 1;
    if (!ports.has(expected)) missing.push(`${region}/${slot}:${expected}`);
  }
}
process.exit(missing.length > 0 ? 1 : 0);
NODE
}

wait_runtime_ready() {
  attempts=0
  while [ "$attempts" -lt "$READINESS_ATTEMPTS" ]; do
    sleep "$READINESS_DELAY_SECONDS"
    if runtime_ready; then
      return 0
    fi
    attempts=$((attempts + 1))
  done
  return 1
}

exports_match_version() {
  expected_version="$1"
  for region in hong-kong taiwan japan singapore united-states south-korea united-kingdom germany france canada australia other; do
    [ -f "$EXPORT_DIR/$region.txt" ] || return 1
  done
  [ -f "$EXPORT_DIR/all.txt" ] || return 1
  [ -f "$EXPORT_DIR/all-plain.txt" ] || return 1
  [ -r "$EXPORT_DIR/README.txt" ] \
    && grep -F "ranking $expected_version" "$EXPORT_DIR/README.txt" >/dev/null 2>&1
}

download() {
  url="$1"
  destination="$2"
  curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --header 'Cache-Control: no-cache' \
    --header 'Pragma: no-cache' \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    --retry 2 \
    --output "$destination" \
    "$url"
}

json_value() {
  file="$1"
  field="$2"
  if command -v jsonfilter >/dev/null 2>&1; then
    jsonfilter -i "$file" -e "@.$field"
  elif command -v jq >/dev/null 2>&1; then
    jq -er ".${field}" "$file"
  elif [ -x "$NODE_BIN" ]; then
    "$NODE_BIN" -e 'const fs=require("fs");const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8"))[process.argv[2]];if(value===undefined||value===null)process.exit(2);process.stdout.write(String(value));' "$file" "$field"
  else
    return 1
  fi
}

urlencode() {
  [ -x "$NODE_BIN" ] || return 1
  "$NODE_BIN" -e 'const encoded=encodeURIComponent(process.argv[1]).replace(/[!\x27()*]/g,(character)=>`%${character.charCodeAt(0).toString(16).toUpperCase()}`);process.stdout.write(encoded);' "$1"
}

if ! command -v "$SHA256_BIN" >/dev/null 2>&1; then
  record_failure 'sha256sum command is unavailable'
fi

# Recover a killed local runtime from the already validated local artifacts.
# This path does not depend on NAS/Sub-Store availability and does not rebuild
# or reorder anything. A later poll will still discover ranking changes.
cached_version=''
[ ! -r "$APPLIED_VERSION_FILE" ] || IFS= read -r cached_version < "$APPLIED_VERSION_FILE" || true
cached_checksum=''
[ ! -r "$APPLIED_CHECKSUM_FILE" ] || IFS= read -r cached_checksum < "$APPLIED_CHECKSUM_FILE" || true
current_checksum=''
if [ -r "$CONFIG_PATH" ]; then
  current_checksum="$(sha256_file "$CONFIG_PATH" 2>/dev/null)" || current_checksum=''
fi
if [ -n "$cached_version" ] \
  && [ -n "$cached_checksum" ] \
  && [ "$current_checksum" = "$cached_checksum" ] \
  && exports_match_version "$cached_version" \
  && ! runtime_ready; then
  log "local-socks runtime is down with coherent local version $cached_version; restarting locally"
  if [ -x "$SERVICE_SCRIPT" ] \
    && "$SERVICE_SCRIPT" restart >/dev/null 2>&1 \
    && wait_runtime_ready; then
    rm -f "$BACKOFF_FILE"
    log "local-socks runtime recovered from local version $cached_version"
    exit 0
  fi
  record_failure 'local-socks runtime self-heal failed'
fi

now_epoch="$(date +%s)"
if [ -s "$BACKOFF_FILE" ]; then
  read -r retry_after _attempts < "$BACKOFF_FILE" || true
  case "${retry_after:-}" in
    *[!0-9]*|'') retry_after=0 ;;
  esac
  if [ "$now_epoch" -lt "$retry_after" ]; then
    exit 0
  fi
fi

STAGE_DIR="$(mktemp -d "$CACHE_DIR/stage.XXXXXX")" || record_failure 'cannot create staging directory'
RANKING_FIRST="$STAGE_DIR/current.first.json"
RANKING_FINAL="$STAGE_DIR/current.json"
SOURCE_YAML="$STAGE_DIR/inventory.yaml"

download "$RANKING_URL" "$RANKING_FIRST" || record_failure 'ranking download failed'
schema="$(json_value "$RANKING_FIRST" schema_version 2>/dev/null)" || record_failure 'ranking JSON is invalid'
version_first="$(json_value "$RANKING_FIRST" version 2>/dev/null)" || record_failure 'ranking version is missing'
if [ "$schema" != '2' ] || [ -z "$version_first" ]; then
  record_failure 'ranking schema is unsupported'
fi

applied_version=''
if [ -r "$APPLIED_VERSION_FILE" ]; then
  IFS= read -r applied_version < "$APPLIED_VERSION_FILE" || true
fi
if [ "$version_first" = "$applied_version" ]; then
  applied_checksum=''
  if [ -r "$APPLIED_CHECKSUM_FILE" ]; then
    IFS= read -r applied_checksum < "$APPLIED_CHECKSUM_FILE" || true
  fi
  actual_checksum=''
  if [ -r "$CONFIG_PATH" ]; then
    actual_checksum="$(sha256_file "$CONFIG_PATH" 2>/dev/null)" || actual_checksum=''
  fi
  if [ -n "$applied_checksum" ] \
    && [ "$actual_checksum" = "$applied_checksum" ] \
    && exports_match_version "$version_first" \
    && stable_ports_match_ranking "$RANKING_FIRST" \
    && [ -x "$SERVICE_SCRIPT" ] \
    && runtime_ready; then
    rm -f "$BACKOFF_FILE"
    exit 0
  fi
  log "ranking version $version_first is current but runtime drift was detected; reapplying"
fi

case "$SOURCE_URL" in
  *'#'*) record_failure 'SOURCE_URL must not contain a fragment' ;;
esac
# Collection names may be customized in Sub-Store. The configured collection
# must nevertheless be the complete, unfiltered inventory; a filtered source
# cannot restore a stable node that temporarily disappeared from its output.
case "$SOURCE_URL" in
  */download/collection/healthy\?*|*/download/collection/healthy\#*|*/download/collection/healthy)
    record_failure 'SOURCE_URL must use the complete inventory collection, not healthy'
    ;;
esac
encoded_version="$(urlencode "$version_first")" || record_failure 'ranking version URL encoding failed'
case "$SOURCE_URL" in
  *'?'*) source_separator='&' ;;
  *) source_separator='?' ;;
esac
SOURCE_VERSION_URL="${SOURCE_URL}${source_separator}_node_health_version=${encoded_version}"
download "$SOURCE_VERSION_URL" "$SOURCE_YAML" || record_failure 'inventory subscription download failed'
if [ ! -s "$SOURCE_YAML" ]; then
  record_failure 'inventory subscription is empty'
fi

download "$RANKING_URL" "$RANKING_FINAL" || record_failure 'ranking consistency download failed'
version_final="$(json_value "$RANKING_FINAL" version 2>/dev/null)" || record_failure 'final ranking version is missing'
schema_final="$(json_value "$RANKING_FINAL" schema_version 2>/dev/null)" || record_failure 'final ranking JSON is invalid'
if [ "$schema_final" != '2' ] || [ "$version_first" != "$version_final" ]; then
  record_failure 'ranking changed during download'
fi

if [ ! -x "$APPLY_COMMAND" ]; then
  record_failure 'apply command is not executable'
fi

CONVERTER_OVERRIDE=''
if [ -n "$STABLE_CONVERTER_URL" ]; then
  CONVERTER_OVERRIDE="$STAGE_DIR/stable-converter.js"
  download "$STABLE_CONVERTER_URL" "$CONVERTER_OVERRIDE" \
    || record_failure 'stable converter download failed'
  [ -s "$CONVERTER_OVERRIDE" ] || record_failure 'stable converter download is empty'
fi

if ! STABLE_CONVERTER_OVERRIDE="$CONVERTER_OVERRIDE" \
  "$APPLY_COMMAND" "$SOURCE_YAML" "$RANKING_FINAL" "$version_final"; then
  record_failure 'validated local-socks apply failed'
fi

applied_checksum="$(sha256_file "$CONFIG_PATH")" || record_failure 'applied config checksum failed'
printf '%s\n' "$applied_checksum" > "$APPLIED_CHECKSUM_FILE.tmp" \
  || record_failure 'cannot write applied config checksum'
mv -f "$APPLIED_CHECKSUM_FILE.tmp" "$APPLIED_CHECKSUM_FILE" \
  || record_failure 'cannot publish applied config checksum'
printf '%s\n' "$version_final" > "$APPLIED_VERSION_FILE.tmp" \
  || record_failure 'cannot write applied ranking version'
mv -f "$APPLIED_VERSION_FILE.tmp" "$APPLIED_VERSION_FILE" \
  || record_failure 'cannot publish applied ranking version'
rm -f "$BACKOFF_FILE"
log "applied ranking version $version_final"
exit 0

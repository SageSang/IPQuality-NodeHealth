// This adapter is derived at runtime from the installed, hash-approved source.
// It never writes or replaces the upstream OpenClash updater.
import crypto from 'node:crypto';
export const SERVICE_SHA256 = '315d674bf3e29ea60bf4b15cb313b35c5689fe14596ed9f3e985620223bddff4';
export const SOURCE_SHA256 = '0842b924b1eba9324666c414f42476c7b55f68411bd1f9c06c8644c415dfd01d';
export function adapt(source) {
  if (crypto.createHash('sha256').update(source).digest('hex') !== SOURCE_SHA256) throw new Error('unsupported_version');
  let value = source.toString();
  const marker = '#分别获取订阅信息进行处理';
  if (value.split(marker).length !== 2) throw new Error('unsupported_version');
  value = value.split(marker)[0]
    .replace('\nset_lock\n', '\n# Parent holds the original lock for the entire transaction.\n')
    .replace('\ninc_job_counter\n', '\n# No upstream job counters or automatic restart in the private candidate builder.\n');
  // Upstream rescues log Ruby errors and may otherwise exit zero. In the private
  // builder both filter and serialization failures must propagate to the caller.
  for (const anchor of [
    "YAML.LOG_ERROR('Filter Proxies Failed,【' + e.message + '】');",
    "YAML.LOG_ERROR('Write file failed:【%s】' % [e.message])",
  ]) {
    if (value.split(anchor).length !== 2) throw new Error('unsupported_version');
    value = value.replace(anchor, () => anchor + '\n exit 1');
  }
  // Original functions are retained for download settings, headers, conversion and keyword filters.
  // Overrides occur after all definitions, before the single configured subscription invocation.
  return value + String.raw`
# sidora-network-v1: fail-closed candidate staging for the approved source hash.
# Do not log subscription URLs/custom headers through the shared OpenClash UI log.
LOG_FILE="$SIDORA_STAGE_LOG"
LOG_OUT() { :; }
LOG_INFO() { :; }
LOG_TIP() { :; }
LOG_ERROR() { :; }
set_lock() { :; }
del_lock() { :; }
inc_job_counter() { :; }
dec_job_counter_and_restart() { :; }
config_error() {
  printf '%s\n' failed > "$SIDORA_STAGE_RESULT"
  rm -f -- "$CFG_FILE"
}
# A failed proxy download must not mutate DNS/firewall/watchdog state as a retry side effect.
config_download_direct() { config_error; }
config_test() {
  "$CLASH" -t -d "$CLASH_CONFIG" -f "$CFG_FILE" -age-secret-key "$SECRET_KEY" >/dev/null 2>&1
}
yaml_sub_validate() {
  YAML_SUB_STATUS=""
  ruby -ryaml -e '
    value = YAML.load_file(ARGV.fetch(0))
    unless value.is_a?(Hash) && (value.key?("proxies") || value.key?("proxy-providers"))
      exit 1
    end
  ' "$CFG_FILE" >> "$LOG_FILE" 2>&1
}
config_su_check() {
  [ "$only_download" -eq 0 ] && [ -s "$CFG_FILE" ] || { config_error; return 1; }
  sed -i 's/!<str> /!!str /g' "$CFG_FILE" || { config_error; return 1; }
  config_cus_up || { config_error; return 1; }
  config_test || { config_error; return 1; }
  cp -- "$CFG_FILE" "$SIDORA_CANDIDATE" || { config_error; return 1; }
  printf '%s\n' staged > "$SIDORA_STAGE_RESULT"
  rm -f -- "$CFG_FILE"
}
# A 304/unchanged download still requires a validated candidate and one explicit restart.
eval "$(declare -f config_download | sed '1s/config_download/original_config_download/')"
config_download() {
  original_config_download
  if [ "$DOWNLOAD_RESULT" -eq 2 ]; then
    cp -- "$CONFIG_FILE" "$CFG_FILE" || { DOWNLOAD_RESULT=1; return; }
    DOWNLOAD_RESULT=0
  fi
}
config_load openclash
printf '%s\n' not_found > "$SIDORA_STAGE_RESULT"
config_foreach sub_info_get config_subscribe "$1"
[ "$(cat "$SIDORA_STAGE_RESULT")" = staged ]
`;
}

export const RC_COMMON_SHA256 = '143c915143c351bd96c5e8007d56e191b78975fd75a32709acd42243d68d230d';
export function adaptInit(source, operationId, nonce) {
  if (crypto.createHash('sha256').update(source).digest('hex') !== SERVICE_SHA256 ||
      !/^[0-9a-f-]{36}$/.test(operationId) || !/^[0-9a-f-]{36}$/.test(nonce)) throw new Error('unsupported_version');
  let value = source.toString();
  const attest = `/usr/bin/node /etc/sidora-network/cli.mjs --attest ${operationId} ${nonce}`;
  const replace = (before, after) => {
    if (value.split(before).length !== 2) throw new Error('unsupported_version');
    value = value.replace(before, () => after);
  };
  // rc.common sources this file before reading initscript/basescript. Keep the real
  // service registration and script pointer; never register the private filename.
  replace('USE_PROCD=1', 'USE_PROCD=1\ninitscript="/etc/init.d/openclash"');
  replace('QUICK_START_CHECK=false\nQUICK_START=true', 'QUICK_START_CHECK=true\nQUICK_START=false');
  replace('cp "$RAW_CONFIG_FILE" "$TMP_CONFIG_FILE"', `cp "$RAW_CONFIG_FILE" "$TMP_CONFIG_FILE" || exit 1\n${attest} source "$$" || exit 1`);
  replace('      mv "$TMP_CONFIG_FILE" "$CONFIG_FILE"', '      mv "$TMP_CONFIG_FILE" "$CONFIG_FILE" || exit 1');
  replace('\n   chown root:root "$CLASH"', `\n   ${attest} produced "$$" || exit 1\n   chown root:root "$CLASH"`);
  const pending = `/etc/sidora-network/state/${operationId}/attempt-${nonce}.pending`;
  replace('procd_set_param command /bin/sh -c "exec $CLASH',
    `procd_set_param command /bin/sh -c "if [ -e '${pending}' ]; then ${attest} launch \\$\\$ || exit 1; fi; exec $CLASH`);
  return value;
}

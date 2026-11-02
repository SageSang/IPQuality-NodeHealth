import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { adaptInit, RC_COMMON_SHA256 } from '../adapter-047156.mjs';
import { fixture, source } from './support.mjs';
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";

test('actual rc.common keeps openclash registration and attests native generated output', { skip: !source }, async () => {
  const originalInit = path.join(path.dirname(source), 'openclash.init');
  const originalRc = path.join(path.dirname(source), 'rc.common');
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(originalRc)).digest('hex'), RC_COMMON_SHA256);
  const f = fixture();
  try {
    await f.baseline();
    const previousProcess = f.tool.process(f.c.core, f.c.runtime_config);
    fs.copyFileSync(path.join(f.root, 'incoming.json'), f.c.raw_config);
    const rawHash = crypto.createHash('sha256').update(fs.readFileSync(f.c.raw_config)).digest('hex');
    const id = crypto.randomUUID(); f.tool.start(id);
    const attempt = f.tool.prepareAttempt(id, 'apply', rawHash);
    const fakeOS = path.join(f.root, 'os');
    for (const dir of ['lib/functions', 'usr/share/openclash', 'tmp', 'etc/openclash/custom']) fs.mkdirSync(path.join(fakeOS, dir), { recursive: true });
    fs.writeFileSync(path.join(fakeOS, 'lib/functions.sh'), 'list_contains() { return 0; }\n');
    fs.writeFileSync(path.join(fakeOS, 'lib/functions/service.sh'), 'true\n');
    fs.writeFileSync(path.join(fakeOS, 'lib/functions/procd.sh'), `
procd_open_service() { printf '%s|%s\\n' "$1" "$2" > '${f.root}/registration'; }
procd_close_service() { :; }
procd_open_instance() { :; }
procd_append_param() { :; }
procd_close_instance() { :; }
procd_lock() { :; }
procd_running() { return 1; }
procd_kill() { :; }
procd_set_param() {
 if [ "$1" = command ] && [ "$2" = /bin/sh ]; then
  shift
  "$@" >/dev/null 2>&1 </dev/null &
  echo "$!" > '${f.root}/core.pid'
 fi
}
`);
    for (const name of ['openclash_ps.sh', 'ruby.sh', 'log.sh', 'uci.sh', 'openclash_curl.sh']) fs.writeFileSync(path.join(fakeOS, 'usr/share/openclash', name), 'true\n');
    const rewrite = path.join(fakeOS, 'usr/share/openclash/yml_change.sh');
    fs.writeFileSync(rewrite, `#!/usr/bin/python3\nimport json,sys\np=${JSON.stringify(path.join(f.root, 'source.yaml'))}\nv=json.load(open(p));v['dns']={'enable':True};json.dump(v,open(p,'w'))\n`);
    fs.chmodSync(rewrite, 0o700);
    fs.writeFileSync(path.join(fakeOS, 'usr/share/openclash/yml_rules_change.sh'), '#!/bin/sh\nexit 0\n');
    fs.chmodSync(path.join(fakeOS, 'usr/share/openclash/yml_rules_change.sh'), 0o700);
    // Preserve the actual service logic and our hooks; redirect OS boundaries only.
    const helper = `${quote(process.execPath)} ${quote(fileURLToPath(new URL('./attest-fixture.mjs', import.meta.url)))} ${quote(f.root)}`;
    let init = adaptInit(fs.readFileSync(originalInit), id, attempt.nonce)
      .replaceAll('/tmp/', '__TEST_TMP__/')
      .replaceAll('/usr/bin/node /etc/sidora-network/cli.mjs --attest', helper)
      .replaceAll(`/etc/sidora-network/state/${id}/`, `${f.c.state_dir}/${id}/`)
      .replaceAll('/usr/share/openclash/', `${fakeOS}/usr/share/openclash/`)
      .replaceAll('$IPKG_INSTROOT' + fakeOS, fakeOS)
      .replaceAll('/etc/openclash/', `${fakeOS}/etc/openclash/`)
      .replaceAll('__TEST_TMP__/', `${fakeOS}/tmp/`);
    init += `
LOG_OUT() { :; }; LOG_WARN() { :; }; LOG_TIP() { :; }; LOG_ERROR() { :; }
uci_get_config() { echo 1; }
get_config() {
 RAW_CONFIG_FILE=${quote(f.c.raw_config)}
 CONFIG_FILE=${quote(f.c.runtime_config)}
 TMP_CONFIG_FILE=${quote(path.join(f.root, 'source.yaml'))}
 CLASH=${quote(f.c.core)}
 CLASH_CONFIG=${quote(f.root)}
 LOG_FILE=${quote(path.join(f.root, 'private.log'))}
}
overwrite_file() { :; }
config_choose() { :; }
do_run_mode() { :; }
do_run_file() { :; }
add_cron() { :; }
check_core_status() { :; }
stop_service() { kill ${previousProcess.pid} 2>/dev/null || true; }
`;
    const privateInit = path.join(f.root, 'private-init'); fs.writeFileSync(privateInit, init);
    const rc = path.join(f.root, 'rc.common'); fs.copyFileSync(originalRc, rc);
    const child = spawnSync('/bin/sh', [rc, privateInit, 'restart'], { env: { ...process.env, IPKG_INSTROOT: fakeOS, PATH: path.join(f.root, 'bin') + ':' + process.env.PATH }, encoding: 'utf8', timeout: 10000 });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(fs.readFileSync(path.join(f.root, 'registration'), 'utf8').trim(), 'openclash|/etc/init.d/openclash');
    await new Promise(resolve => setTimeout(resolve, 200));
    const proof = JSON.parse(fs.readFileSync(f.tool.attemptFile(id, attempt.nonce)));
    assert.equal(proof.phase, 'launched', JSON.stringify(proof));
    assert.notEqual(proof.source_sha256, proof.runtime_sha256); // native synthetic overwrite ran
    const result = await f.tool.verify(previousProcess, rawHash, null, {}, attempt);
    assert.equal(result.verified, true);
    assert.equal((await f.tool.snapshot()).identity_verified, true);
  } finally { f.close(); }
});

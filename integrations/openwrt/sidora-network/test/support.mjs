import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { Toolkit } from '../toolkit.mjs';
const require = createRequire(import.meta.url);
const yaml = require('js-yaml');
const converter = require('../../../local-socks/convert-any-proxy-to-local-socks-stable.js');
export const source = process.env.OPENCLASH_TEST_SOURCE;
export function fixture(root = fs.mkdtempSync(path.join(os.tmpdir(), 'sidora-router-test-')), mode = 'normal') {
  fs.mkdirSync(root, { recursive: true });
  fs.chmodSync(root, 0o700);
  const rawDir = path.join(root, 'raw'), runtimeDir = path.join(root, 'live'), tmp = path.join(root, 'tmp');
  for (const dir of [rawDir, runtimeDir, tmp, path.join(root, 'bin')]) fs.mkdirSync(dir, { recursive: true });
  const c = { raw_config: path.join(rawDir, 'synthetic.yaml'), runtime_config: path.join(runtimeDir, 'synthetic.yaml'),
    updater: path.join(root, 'updater.sh'), core: path.join(root, 'core'), service: path.join(root, 'service.py'),
    state_dir: path.join(root, 'state'), local_socks_core: path.join(root, 'other-core'), local_socks_config: path.join(root, 'other.yaml'),
    local_socks_cache: path.join(root, 'local-cache'), converter: '', controller_url: 'http://127.0.0.1:1', controller_token_file: path.join(root, 'token') };
  if (source) fs.copyFileSync(source, c.updater); else fs.writeFileSync(c.updater, 'synthetic-unapproved');
  const config = {
    proxies: [{ name: 'A', type: 'ss', server: 'old.example', port: 443, cipher: 'aes-128-gcm', password: 'synthetic-secret' },
      { name: 'B', type: 'ss', server: 'other.example', port: 443, cipher: 'aes-128-gcm', password: 'synthetic-secret' }],
    'proxy-groups': [{ name: 'US', type: 'fallback', proxies: ['A', 'B'] }, { name: 'ChatGPT', type: 'select', proxies: ['US', 'DIRECT'] }],
  };
  if (!fs.existsSync(c.raw_config)) {
    fs.writeFileSync(c.raw_config, JSON.stringify(config));
    fs.writeFileSync(c.runtime_config, JSON.stringify(config));
    const next = structuredClone(config);
    next.proxies[0].server = 'new.example'; next['proxy-groups'][0].proxies.reverse();
    fs.writeFileSync(path.join(root, 'incoming.json'), JSON.stringify(next));
    fs.writeFileSync(path.join(root, 'mode'), mode);
    fs.writeFileSync(path.join(root, 'choices.json'), JSON.stringify({ ChatGPT: 'DIRECT' }));
  }
  fs.writeFileSync(path.join(root, 'core.c'), '#include <signal.h>\n#include <string.h>\n#include <unistd.h>\nint main(int n,char**v){for(int i=0;i<n;i++)if(!strcmp(v[i],"-t"))return 0;for(;;)pause();}\n');
  if (!fs.existsSync(c.core)) {
    const result = spawnSync('cc', ['-O2', path.join(root, 'core.c'), '-o', c.core]);
    if (result.status) throw new Error('cc fixture failed');
  }
  // This service is an isolated process double, not a real system service.
  fs.writeFileSync(c.service, `#!/usr/bin/python3
import os,json,signal,subprocess,time,sys,shlex,shutil
from pathlib import Path
r=Path(${JSON.stringify(root)})
with (r/'restart.log').open('a') as f:f.write('restart\\n')
mode=(r/'mode').read_text()
operation=sys.argv[2:]
helper=[${JSON.stringify(process.execPath)},${JSON.stringify(fileURLToPath(new URL('./attest-fixture.mjs', import.meta.url)))},str(r)]
def attest(stage):
 if operation:subprocess.run(helper+operation+[stage,str(os.getpid())],check=True)
new='new.example' in (r/'raw/synthetic.yaml').read_text()
if mode=='ignore' and new:raise SystemExit(0)
if mode=='fail-all':raise SystemExit(1)
if mode=='slow':time.sleep(.8)
if mode=='reset-choices':(r/'choices.json').write_text('{}')
pid=r/'core.pid'
if pid.exists():
 try:os.kill(int(pid.read_text()),signal.SIGTERM)
 except ProcessLookupError:pass
time.sleep(.03)
shutil.copyfile(r/'raw/synthetic.yaml', r/'source.yaml')
attest('source')
if mode!='stale-runtime' or not new:
 (r/'live/synthetic.yaml').write_bytes((r/'source.yaml').read_bytes())
 attest('produced')
launch='exec '+shlex.quote(str(r/'core'))+' -f '+shlex.quote(str(r/'live/synthetic.yaml'))
if operation and (mode!='stale-runtime' or not new):
 launch=' '.join(shlex.quote(v) for v in helper+operation+['launch'])+' $$ && '+launch
p=subprocess.Popen(['/bin/sh','-c',launch],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pid.write_text(str(p.pid))
`);
  fs.chmodSync(c.service, 0o700);
  const lib = path.join(root, 'library.sh');
  fs.writeFileSync(lib, `config_load() { :; }
config_get_bool() { printf -v "$1" '%s' 1; }
config_get() {
  local val=''
  case "$3" in name) val=synthetic;; sub_convert) val=0;; address) val='https://synthetic.invalid/feed';; sub_ua) val=synthetic;; esac
  printf -v "$1" '%s' "$val"
}
config_list_foreach() { :; }
config_foreach() { "$1" sample "$3"; }
uci_get_config() { case "$1" in config_path) printf '%s' '${c.raw_config}';; *) printf '0';; esac; }
uci_get_age_secret_keys() { :; }
LOG_OUT() { :; }; LOG_TIP() { :; }; LOG_INFO() { :; }; LOG_ERROR() { :; }
DOWNLOAD_FILE_CURL() {
  case "$(cat '${path.join(root, 'mode')}')" in download-fail) return 1;; unchanged) return 2;; esac
  cp '${path.join(root, 'incoming.json')}' "$2"
}
`);
  fs.writeFileSync(path.join(root, 'bin/ruby'), '#!/bin/sh\nexit 0\n');
  fs.chmodSync(path.join(root, 'bin/ruby'), 0o700);
  const dependencies = { yaml, converter, attempts: 3, delay: 25, sourceTemporaryPath: path.join(root, "source.yaml"), serviceHash: crypto.createHash("sha256").update(fs.readFileSync(c.service)).digest("hex"),
    lockHeld: () => !fs.existsSync(path.join(root, 'lost-lock')),
    busyJobs: () => fs.existsSync(path.join(root, 'busy-jobs')),
    command(file, args, options) {
      if (file === 'uci') return { status: 0, stdout: c.raw_config };
      return spawnSync(file, args, options);
    },
    async controller(method = 'GET', suffix, body) {
      const loaded = JSON.parse(fs.readFileSync(c.runtime_config));
      const choices = JSON.parse(fs.readFileSync(path.join(root, 'choices.json')));
      const values = Object.fromEntries(loaded.proxies.map(p => [p.name, { type: 'Shadowsocks' }]));
      for (const g of loaded['proxy-groups']) values[g.name] = { type: g.type === 'select' ? 'Selector' : 'Fallback', all: g.proxies,
        now: choices[g.name] || g.proxies[0], fixed: '' };
      if (method !== 'GET') {
        choices[decodeURIComponent(suffix.slice('/proxies/'.length))] = body.name;
        fs.writeFileSync(path.join(root, 'choices.json'), JSON.stringify(choices));
        return {};
      }
      return values;
    },
    commandAsync(file, args, options) {
      if (file === '/bin/bash') {
        // Run the real hash-derived builder with only its OS service boundaries redirected.
        let script = fs.readFileSync(args[0], 'utf8').replace(/^\. .+$/gm, `. '${lib}'`)
          .replaceAll('/etc/openclash/config/', rawDir + '/')
          .replace('CLASH="/etc/openclash/clash"', `CLASH="${c.core}"`)
          .replace('CFG_FILE="/tmp/$name.yaml"', `CFG_FILE="${tmp}/$name.yaml"`)
          .replaceAll('/tmp/yaml_sub_status', tmp + '/yaml_sub_status')
          .replace('LOG_FILE="/tmp/openclash.log"', `LOG_FILE="${tmp}/log"`);
        const destination = args[0] + '.isolated.sh';
        fs.writeFileSync(destination, script, { mode: 0o600 });
        args = [destination, ...args.slice(1)];
        options = { ...options, env: { ...options.env, PATH: path.join(root, 'bin') + ':' + options.env.PATH } };
      }
      return new Promise(resolve => {
        const child = spawn(file, args, { ...options, stdio: ['ignore', 'ignore', 'pipe'] });
        let diagnostic = '';
        child.stderr.on('data', chunk => { diagnostic += chunk; });
        child.on('exit', code => { if (code) fs.writeFileSync(path.join(root, 'test-error.log'), diagnostic); resolve(code === 0); });
        child.on('error', () => resolve(false));
      });
    },
    async restartAttested(attempt) {
      if (!await dependencies.commandAsync(c.service, ['restart', attempt.id, attempt.nonce])) throw new Error('restart_failed');
    },
    launch() {},
  };
  fs.mkdirSync(c.state_dir, { recursive: true, mode: 0o700 });
  const tool = new Toolkit(c, dependencies);
  return { root, c, tool, dependencies, config,
    async baseline() {
      if (spawnSync(c.service, ['restart']).status) throw new Error('baseline failed');
      await new Promise(r => setTimeout(r, 60));
    },
    close() {
      try { process.kill(Number(fs.readFileSync(path.join(root, 'core.pid'))), 'SIGTERM'); } catch { /* fixture */ }
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

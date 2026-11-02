import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';
import { createRequire } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';
import { adapt, adaptInit, SOURCE_SHA256, SERVICE_SHA256, RC_COMMON_SHA256 } from './adapter-047156.mjs';

const require = createRequire(import.meta.url);
const protocol = 'sidora-network-v1';
const terminal = new Set(['succeeded', 'failed', 'rolled_back']);
const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
function pidIdentity(pid) {
  if (!Number.isInteger(pid) || pid <= 1) throw new Error('process_invalid');
  const stat = fs.readFileSync(`/proc/${pid}/stat`).toString().split(') ')[1].split(' ');
  return { pid, started: stat[19], boot_id: fs.readFileSync('/proc/sys/kernel/random/boot_id').toString().trim() };
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function read(file, maximum = 16 * 1024 * 1024) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > maximum) throw new Error('configuration_invalid');
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}
function fileDigest(file, follow = false) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (follow ? 0 : fs.constants.O_NOFOLLOW));
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size > 256 * 1024 * 1024) throw new Error('configuration_invalid');
    const digest = crypto.createHash('sha256'), buffer = Buffer.alloc(65536);
    let length;
    while ((length = fs.readSync(fd, buffer, 0, buffer.length, null)) !== 0) digest.update(buffer.subarray(0, length));
    const after = fs.fstatSync(fd);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error('configuration_invalid');
    return digest.digest('hex');
  } finally { fs.closeSync(fd); }
}
const readJSON = file => JSON.parse(read(file).toString());
function write(file, value, expectedHash = null) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {
    const fd = fs.openSync(temporary, 'wx', 0o600);
    try { fs.writeFileSync(fd, value); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    if (expectedHash !== null) {
      let current;
      try { current = hash(read(file)); } catch { throw new Error('rollback_conflict'); }
      if (current !== expectedHash) throw new Error('rollback_conflict');
    }
    fs.renameSync(temporary, file);
    const dir = fs.openSync(path.dirname(file), 'r');
    try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } finally { try { fs.unlinkSync(temporary); } catch { /* renamed or not created */ } }
}
const writeJSON = (file, value) => write(file, JSON.stringify(value) + '\n');
function privateFile(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.uid !== 0 || stat.mode & 0o077) throw new Error('configuration_invalid');
}
export function loadConfiguration(file) {
  privateFile(file);
  const value = readJSON(file);
  const required = ['raw_config', 'runtime_config', 'updater', 'service', 'core', 'state_dir', 'controller_url',
    'controller_token_file', 'converter', 'local_socks_cache', 'local_socks_config', 'local_socks_core'];
  if (value.schema_version !== 1 || Object.keys(value).some(k => ![...required, 'schema_version', 'update_mode', 'refresh_sha256'].includes(k)) ||
    required.some(k => typeof value[k] !== 'string')) throw new Error('configuration_invalid');
  const url = new URL(value.controller_url);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('configuration_invalid');
  for (const key of required.filter(k => k !== 'controller_url')) {
    if (!path.isAbsolute(value[key]) || /[\n\r\0]/.test(value[key])) throw new Error('configuration_invalid');
  }
  if (!value.raw_config.startsWith('/etc/openclash/config/') || path.dirname(value.raw_config) !== '/etc/openclash/config' ||
    path.dirname(value.runtime_config) !== '/etc/openclash' || path.basename(value.runtime_config) !== path.basename(value.raw_config) ||
    value.updater !== '/usr/share/openclash/openclash.sh' || value.service !== '/etc/init.d/openclash' ||
    !['/etc/openclash/clash', '/etc/openclash/core/clash_meta'].includes(value.core) || value.state_dir !== '/etc/sidora-network/state' ||
    value.converter !== '/etc/local-socks/convert-any-proxy-to-local-socks-stable.js' ||
    value.local_socks_cache !== '/etc/local-socks/cache/node-health' || value.local_socks_config !== '/etc/local-socks/config.yaml' ||
    value.local_socks_core !== '/etc/local-socks/bin/mihomo-local-socks') throw new Error('configuration_invalid');
  // Profile names originate in trusted config but are interpolated by the old upstream Ruby code.
  if (/['"`$\\\n\r]/.test(path.basename(value.raw_config))) throw new Error('configuration_invalid');
  if (value.update_mode && value.update_mode !== 'catalog_hot_reload') throw new Error('configuration_invalid');
  if (value.update_mode && !/^[a-f0-9]{64}$/.test(value.refresh_sha256 || '')) throw new Error('configuration_invalid');
  privateFile(value.controller_token_file);
  value.controller_url = value.controller_url.replace(/\/$/, '');
  return value;
}

export class Toolkit {
  constructor(config, dependencies = {}) {
    this.c = config;
    this.deps = dependencies;
    this.yaml = dependencies.yaml || require('js-yaml');
    this.converter = dependencies.converter || require(config.converter);
    if (this.converter.CONSUMER_CONTRACT !== 'local-socks-explicit-v1') throw new Error('configuration_invalid');
    const stateStat = fs.lstatSync(config.state_dir);
    if (!stateStat.isDirectory() || stateStat.uid !== process.getuid() || stateStat.mode & 0o077) throw new Error('configuration_invalid');
  }
  directory(id) {
    if (!idPattern.test(id || '')) throw new Error('configuration_invalid');
    return path.join(this.c.state_dir, id);
  }
  receipt(id) {
    try { return readJSON(path.join(this.directory(id), 'receipt.json')); }
    catch (error) { if (error.code === 'ENOENT') throw new Error('unknown_operation'); throw error; }
  }
  save(id, updates) {
    const value = { ...this.receipt(id), ...updates, updated_at: now() };
    writeJSON(path.join(this.directory(id), 'receipt.json'), value);
    return value;
  }
  command(file, args, options = {}) {
    return (this.deps.command || spawnSync)(file, args, { encoding: 'utf8', timeout: 30000,
      maxBuffer: 2 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'], ...options });
  }
  approved() {
    if (this.c.update_mode === 'catalog_hot_reload') {
      if (hash(read('/etc/local-socks/openclash-refresh.mjs')) !== this.c.refresh_sha256) throw new Error('unsupported_version');
      return;
    }
    if (hash(read(this.c.updater)) !== SOURCE_SHA256 || hash(read(this.c.service)) !== (this.deps.serviceHash || SERVICE_SHA256)) throw new Error('unsupported_version');
    if (!this.deps.restartAttested && hash(read('/etc/rc.common')) !== RC_COMMON_SHA256) throw new Error('unsupported_version');
    const selected = this.command('uci', ['-q', 'get', 'openclash.config.config_path']);
    if (selected.status !== 0 || selected.stdout.trim() !== this.c.raw_config) throw new Error('configuration_invalid');
  }
  process(core, configuration) {
    if (this.deps.process) return this.deps.process(core, configuration);
    let expected;
    try { expected = fileDigest(fs.realpathSync(core)); } catch { return null; }
    for (const name of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(name)) continue;
      try {
        const args = fs.readFileSync(`/proc/${name}/cmdline`).toString().split('\0');
        const position = args.indexOf('-f');
        if (position < 0 || args[position + 1] !== configuration || fileDigest(`/proc/${name}/exe`, true) !== expected) continue;
        return pidIdentity(Number(name));
      } catch { /* Not the requested process. */ }
    }
    return null;
  }
  async controller(method = "GET", suffix = "/proxies", body = undefined) {
    if (this.deps.controller) return this.deps.controller(method, suffix, body);
    const token = read(this.c.controller_token_file, 4096).toString().trim();
    if (!token || /[\r\n]/.test(token)) throw new Error('configuration_invalid');
    return new Promise((resolve, reject) => {
      const request = http.request(this.c.controller_url + suffix, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }, response => {
        let size = 0; const parts = [];
        response.on('data', part => {
          size += part.length;
          if (size > 2 * 1024 * 1024) request.destroy(new Error('response_invalid'));
          else parts.push(part);
        });
        response.on('end', () => {
          try {
            if (method !== 'GET' && response.statusCode === 204) { resolve({}); return; }
            if (response.statusCode !== 200) throw new Error('response_invalid');
            const value = JSON.parse(Buffer.concat(parts));
            if (!value.proxies || typeof value.proxies !== 'object') throw new Error('response_invalid');
            resolve(value.proxies);
          } catch { reject(new Error('response_invalid')); }
        });
        response.on('error', reject);
      });
      const timer = setTimeout(() => request.destroy(new Error('controller_timeout')), 8000);
      request.on('close', () => clearTimeout(timer));
      request.on('error', reject);
      request.end(body === undefined ? undefined : JSON.stringify(body));
    });
  }
  async snapshot() {
    const before = this.process(this.c.core, this.c.runtime_config);
    const raw = read(this.c.runtime_config);
    const config = this.yaml.load(raw.toString());
    const proxies = await this.controller();
    const after = this.process(this.c.core, this.c.runtime_config);
    const declared = Array.isArray(config?.proxies) ? config.proxies : [];
    const groups = Array.isArray(config?.['proxy-groups']) ? config['proxy-groups'] : [];
    let verified = Boolean(before && after && JSON.stringify(before) === JSON.stringify(after) && hash(read(this.c.runtime_config)) === hash(raw));
    // Every configured static group must agree with the controller's ordered candidates.
    for (const group of groups) {
      if (Array.isArray(group.proxies) && !group.use?.length &&
        JSON.stringify(proxies[group.name]?.all) !== JSON.stringify(group.proxies)) verified = false;
    }
    if (!declared.length || !groups.length) verified = false;
    const names = new Set();
    const nodes = declared.map(proxy => {
      const name = proxy.name;
      if (typeof name !== 'string' || !proxies[name] || names.has(name)) verified = false;
      names.add(name);
      return { name, node_key: this.converter.nodeKey(proxy) };
    });
    // A prior verified restart can bind this process to this exact file. Do not infer field identity
    // merely from equal proxy names on a pre-existing process or an externally modified file.
    let proof;
    try { proof = readJSON(path.join(this.c.state_dir, 'loaded.json')); } catch { proof = null; }
    const bound = proof?.schema_version === 2 && /^[a-f0-9]{64}$/.test(proof?.attestation_sha256 || "") && proof?.runtime_configuration_sha256 === hash(raw) && JSON.stringify(proof?.process) === JSON.stringify(after);
    return { protocol, observed_at: now(), identity_verified: verified && bound, configuration_sha256: hash(raw),
      process: after, nodes: verified && bound ? nodes : [], groups_verified: verified };
  }
  fixedPorts() {
    const receiptBytes = read(path.join(this.c.local_socks_cache, 'applied.json'));
    const receipt = JSON.parse(receiptBytes);
    if (!idPattern.test(receipt.generation_id || '')) throw new Error('configuration_invalid');
    const generation = path.join(this.c.local_socks_cache, 'generations', receipt.generation_id);
    const manifest = readJSON(path.join(generation, 'manifest.json'));
    const verified = receipt.config_sha256 === hash(read(this.c.local_socks_config)) &&
      receipt.config_sha256 === hash(read(path.join(generation, 'config.yaml'))) &&
      receipt.core_sha256 === fileDigest(fs.realpathSync(this.c.local_socks_core)) &&
      receipt.manifest_hash === this.converter.digest(manifest) &&
      Boolean(this.process(this.c.local_socks_core, this.c.local_socks_config)) &&
      hash(read(path.join(this.c.local_socks_cache, 'applied.json'))) === hash(receiptBytes);
    const entries = Array.isArray(manifest) ? manifest.map(item => Object.fromEntries(
      ['region', 'slot', 'port', 'node_key', 'name'].filter(key => Object.hasOwn(item, key)).map(key => [key, item[key]]))) : [];
    return { protocol, verified, observed_at: now(), mapping_version: receipt.mapping_version,
      ranking_version: receipt.ranking_version, applied_at: receipt.applied_at, entries: verified ? entries : [] };
  }
  start(id) {
    const directory = this.directory(id);
    // mkdir is a brief request serialization lock. Worker liveness is represented separately.
    const guard = path.join(this.c.state_dir, 'launch.lock');
    try { fs.mkdirSync(guard, { mode: 0o700 }); }
    catch { throw new Error('busy'); }
    try {
      if (fs.existsSync(path.join(directory, 'receipt.json'))) return this.operation(id);
      this.approved();
      const activeFile = path.join(this.c.state_dir, 'active.json');
      if (fs.existsSync(activeFile)) {
        const active = this.operation(readJSON(activeFile).operation_id);
        if (!terminal.has(active.state)) throw new Error('busy');
      }
      fs.mkdirSync(directory, { mode: 0o700 });
      const value = { protocol, operation_id: id, state: 'running', phase: 'queued', created_at: now(), updated_at: now(),
        source_sha256: SOURCE_SHA256, result: {}, error_code: null };
      writeJSON(path.join(directory, 'receipt.json'), value);
      writeJSON(activeFile, { operation_id: id });
      if (this.deps.launch) this.deps.launch(id);
      else {
        const child = spawn('/bin/bash', [this.c.update_mode === 'catalog_hot_reload' ? '/etc/sidora-network/hot-worker.sh' : '/etc/sidora-network/worker.sh', id], { detached: true, stdio: 'ignore', env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8' } });
        child.on('error', () => this.save(id, { state: 'unknown', phase: 'unknown', error_code: 'launch_unconfirmed' }));
        child.unref();
      }
      return value;
    } finally { fs.rmdirSync(guard); }
  }
  operation(id) {
    const value = this.receipt(id);
    // Never replay a dead worker: read status keeps the operation uncertain and holds the target.
    if (!terminal.has(value.state) && Date.now() - Date.parse(value.updated_at) > 15 * 60 * 1000) {
      return this.save(id, { state: 'unknown', phase: 'unknown', error_code: 'worker_unconfirmed' });
    }
    return value;
  }
  failBusy(id) { return this.save(id, { state: 'failed', phase: 'failed', error_code: 'subscription_busy' }); }
  lockHeld() {
    if (this.deps.lockHeld) return this.deps.lockHeld();
    try {
      const fd = fs.fstatSync(9), current = fs.statSync('/tmp/lock/openclash_subs.lock');
      return fd.ino === current.ino && fd.dev === current.dev;
    } catch { return false; }
  }
  busyJobs() {
    if (this.deps.busyJobs) return this.deps.busyJobs();
    try {
      const content = read('/tmp/openclash_jobs', 100).toString().trim().split(/\s+/).map(Number);
      return content[0] !== 0 || content[1] !== 0;
    } catch (error) { return error.code !== 'ENOENT'; }
  }
  async commandAsync(file, args, options) {
    if (this.deps.commandAsync) return this.deps.commandAsync(file, args, options);
    return new Promise(resolve => {
      const child = spawn(file, args, { stdio: 'ignore', ...options, detached: true });
      let killTimer, timedOut = false;
      const signal = name => { try { process.kill(-child.pid, name); } catch { /* already gone */ } };
      const timer = setTimeout(() => {
        timedOut = true; signal('SIGTERM');
        killTimer = setTimeout(() => signal('SIGKILL'), 5000);
      }, 180000);
      const done = result => { clearTimeout(timer); clearTimeout(killTimer); resolve(result); };
      child.once('error', () => done(false));
      child.once('exit', code => done(code === 0 && !timedOut));
    });
  }
  async restoreSelections(choices) {
    const current = await this.controller(), expected = [], unavailable = [];
    for (const [name, choice] of Object.entries(choices)) {
      const selected = choice.type === 'Selector' ? choice.now : choice.fixed;
      if (!selected || !['Selector', 'Fallback', 'URLTest'].includes(choice.type)) continue;
      const value = current[name];
      if (value?.type !== choice.type || !value?.all?.includes(selected)) {
        unavailable.push({ group: name, reason: value?.type !== choice.type ? 'group_changed' : 'candidate_removed' });
        continue;
      }
      expected.push({ group: name, selected, type: choice.type });
      const retained = choice.type === 'Selector' ? value.now === selected : value.fixed === selected;
      if (!retained) await this.controller('PUT', '/proxies/' + encodeURIComponent(name), { name: selected });
    }
    // A 204 only acknowledges a write. Always read back the effective persisted choice.
    const after = await this.controller();
    for (const expectedChoice of expected) {
      const value = after[expectedChoice.group];
      if (value?.type !== expectedChoice.type || !value?.all?.includes(expectedChoice.selected) ||
          (expectedChoice.type === 'Selector' ? value.now !== expectedChoice.selected : value.fixed !== expectedChoice.selected)) {
        throw new Error('selection_not_restored');
      }
    }
    return { restored: expected.map(value => value.group), unavailable };
  }
  attemptFile(id, nonce) {
    if (!idPattern.test(nonce || '')) throw new Error('configuration_invalid');
    return path.join(this.directory(id), `attempt-${nonce}.json`);
  }
  prepareAttempt(id, purpose, sourceHash) {
    const nonce = crypto.randomUUID();
    const value = { schema_version: 1, operation_id: id, nonce, purpose, phase: 'prepared',
      source_sha256: sourceHash, core_sha256: fileDigest(fs.realpathSync(this.c.core)),
      runtime_before_sha256: hash(read(this.c.runtime_config)) };
    writeJSON(this.attemptFile(id, nonce), value);
    write(this.attemptFile(id, nonce).replace(/\.json$/, ".pending"), "pending\n");
    return { id, nonce };
  }
  attest(id, nonce, stage, pid) {
    // Local-only hook inside the exact reviewed private init; SSH grammar exposes no hook.
    const file = this.attemptFile(id, nonce), value = readJSON(file);
    if (value.operation_id !== id || value.nonce !== nonce || Number(pid) !== process.ppid ||
        hash(read(this.c.raw_config)) !== value.source_sha256 ||
        fileDigest(fs.realpathSync(this.c.core)) !== value.core_sha256) throw new Error('attestation_invalid');
    const producer = pidIdentity(Number(pid));
    if (stage === 'source') {
      if (value.phase !== 'prepared' || hash(read(this.deps.sourceTemporaryPath || path.join('/tmp', path.basename(this.c.raw_config)))) !== value.source_sha256) throw new Error('attestation_invalid');
      value.source_producer = producer;
      value.phase = 'source_checked';
    } else if (stage === 'produced') {
      if (value.phase !== 'source_checked' || JSON.stringify(value.source_producer) !== JSON.stringify(producer)) throw new Error('attestation_invalid');
      value.runtime_sha256 = hash(read(this.c.runtime_config));
      value.phase = 'produced';
    } else if (stage === 'launch') {
      if (!['produced', 'launched'].includes(value.phase) || hash(read(this.c.runtime_config)) !== value.runtime_sha256) throw new Error('attestation_invalid');
      value.launched_process = producer;
      value.phase = 'launched';
    } else throw new Error('attestation_invalid');
    writeJSON(file, value);
    if (stage === "launch") fs.unlinkSync(file.replace(/\.json$/, ".pending"));
    return value;
  }
  async restartAttested(id, purpose, sourceHash) {
    const attempt = this.prepareAttempt(id, purpose, sourceHash);
    const privateInit = path.join(this.directory(id), `openclash-${attempt.nonce}`);
    try {
      if (this.deps.restartAttested) {
        await this.deps.restartAttested(attempt);
      } else {
        if (hash(read('/etc/rc.common')) !== RC_COMMON_SHA256) throw new Error('unsupported_version');
        write(privateInit, adaptInit(read(this.c.service), id, attempt.nonce));
        if (!await this.commandAsync('/bin/sh', ['/etc/rc.common', privateInit, 'restart'])) throw new Error('restart_failed');
      }
      return attempt;
    } catch (error) { error.attempt = attempt; throw error; }
    finally { try { fs.unlinkSync(privateInit); } catch { /* private recovery state */ } }
  }
  async verify(previousProcess, rawHash, localProcess, choices = {}, attempt = null) {
    // A new PID and two unrelated hashes cannot prove that this subscription reached the core.
    if (!attempt) throw new Error('runtime_attestation_required');
    for (let i = 0; i < (this.deps.attempts || 20); i++) {
      try {
        const proof = readJSON(this.attemptFile(attempt.id, attempt.nonce));
        const snapshot = await this.snapshot();
        if (proof.phase !== 'launched' || proof.source_sha256 !== rawHash ||
            proof.runtime_sha256 !== snapshot.configuration_sha256 ||
            JSON.stringify(proof.launched_process) !== JSON.stringify(snapshot.process) ||
            fileDigest(fs.realpathSync(this.c.core)) !== proof.core_sha256 ||
            !snapshot.groups_verified || !snapshot.process ||
            JSON.stringify(snapshot.process) === JSON.stringify(previousProcess) ||
            hash(read(this.c.raw_config)) !== rawHash ||
            JSON.stringify(this.process(this.c.local_socks_core, this.c.local_socks_config)) !== JSON.stringify(localProcess)) {
          throw new Error('runtime_not_attested');
        }
        const selections = await this.restoreSelections(choices);
        // Readback must still belong to that exact launched process and immutable runtime artifact.
        if (JSON.stringify(this.process(this.c.core, this.c.runtime_config)) !== JSON.stringify(proof.launched_process) ||
            hash(read(this.c.runtime_config)) !== proof.runtime_sha256 || hash(read(this.c.raw_config)) !== rawHash) throw new Error('runtime_not_attested');
        writeJSON(path.join(this.c.state_dir, 'loaded.json'), { schema_version: 2,
          attestation_sha256: hash(JSON.stringify(proof)), operation_id: attempt.id, attempt_nonce: attempt.nonce, process: snapshot.process,
          runtime_configuration_sha256: snapshot.configuration_sha256 });
        return { verified: true, configuration_sha256: rawHash, runtime_configuration_sha256: snapshot.configuration_sha256,
          process_id: snapshot.process.pid, process_started: snapshot.process.started, local_socks_unchanged: true, selections };
      } catch (error) {
        if (error.message === 'selection_not_restored') throw error;
      }
      await sleep(this.deps.delay ?? 1500);
    }
    throw new Error('verification_failed');
  }
  async work(id) {
    if (this.c.update_mode === 'catalog_hot_reload') {
      const {work} = await import('./hot-reload.mjs');
      return work(this, id);
    }
    const directory = this.directory(id);
    let replaced = false, previousProcess, localProcess, previousHash, ownedHash, applyAttempt, runtimeBefore, choices = {};
    try {
      this.approved();
      if (!this.lockHeld() || this.busyJobs()) return this.failBusy(id);
      const receipt = this.receipt(id);
      if (terminal.has(receipt.state) || receipt.phase !== 'queued') return; // one worker attempt only
      const original = read(this.c.raw_config);
      previousHash = hash(original);
      runtimeBefore = hash(read(this.c.runtime_config));
      previousProcess = this.process(this.c.core, this.c.runtime_config);
      localProcess = this.process(this.c.local_socks_core, this.c.local_socks_config);
      if (!previousProcess) throw new Error('baseline_unverified');
      const current = await this.controller();
      choices = Object.fromEntries(Object.entries(current).filter(([,v]) => v.type === 'Selector' || v.fixed).map(([name,v]) => [name, { type: v.type, now: v.now, fixed: v.fixed }]));
      writeJSON(path.join(directory, 'selections.json'), choices);
      write(path.join(directory, 'previous.yaml'), original);
      write(path.join(directory, 'previous-runtime.yaml'), read(this.c.runtime_config));
      const builder = path.join(directory, 'builder.sh');
      write(builder, adapt(read(this.c.updater)));
      this.save(id, { phase: 'downloading' });
      const candidate = path.join(directory, 'candidate.yaml');
      const staged = await this.commandAsync('/bin/bash', [builder, this.c.raw_config], {
        env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8', SIDORA_CANDIDATE: candidate,
          SIDORA_STAGE_RESULT: path.join(directory, 'stage-result'), SIDORA_STAGE_LOG: path.join(directory, 'stage-private.log') } });
      if (!staged || read(path.join(directory, 'stage-result'), 100).toString().trim() !== 'staged') throw new Error('download_failed');
      this.save(id, { phase: 'validating' });
      const rendered = this.yaml.load(read(candidate).toString());
      if (!rendered || (!rendered.proxies?.length && !Object.keys(rendered['proxy-providers'] || {}).length)) throw new Error('candidate_invalid');
      const check = this.command(this.c.core, ['-t', '-d', '/etc/openclash', '-f', candidate]);
      if (check.status !== 0 || check.error) throw new Error('candidate_invalid');
      if (!this.lockHeld() || this.busyJobs() || hash(read(this.c.raw_config)) !== previousHash) throw new Error('baseline_changed');
      const selected = this.command('uci', ['-q', 'get', 'openclash.config.config_path']);
      if (selected.stdout.trim() !== this.c.raw_config) throw new Error('baseline_changed');
      this.save(id, { phase: 'restarting' });
      // Persist before replacement; a killed worker must be diagnosed, never auto-replayed.
      writeJSON(path.join(directory, 'replacement.json'), { previous_sha256: previousHash, candidate_sha256: hash(read(candidate)) });
      ownedHash = hash(read(candidate));
      write(this.c.raw_config, read(candidate), previousHash);
      replaced = true;
      try { applyAttempt = await this.restartAttested(id, 'apply', ownedHash); }
      catch (error) { applyAttempt = error.attempt; throw error; }
      this.save(id, { phase: 'verifying' });
      const result = await this.verify(previousProcess, ownedHash, localProcess, choices, applyAttempt);
      result.previous_configuration_sha256 = previousHash;
      this.save(id, { state: 'succeeded', phase: 'completed', result });
    } catch (error) {
      if (replaced) {
        this.save(id, { phase: 'rolling_back' });
        try {
          if (!this.lockHeld() || hash(read(this.c.raw_config)) !== ownedHash) throw new Error('rollback_conflict');
          // Only replace this operation's candidate. Preserve an independently edited runtime too.
          const attemptProof = applyAttempt ? readJSON(this.attemptFile(applyAttempt.id, applyAttempt.nonce)) : null;
          const currentRuntime = hash(read(this.c.runtime_config));
          if (currentRuntime !== runtimeBefore && currentRuntime !== attemptProof?.runtime_sha256) throw new Error('rollback_conflict');
          const beforeRecovery = this.process(this.c.core, this.c.runtime_config);
          write(this.c.raw_config, read(path.join(directory, 'previous.yaml')), ownedHash);
          const recoveryAttempt = await this.restartAttested(id, 'rollback', previousHash);
          const result = await this.verify(beforeRecovery, previousHash, localProcess, choices, recoveryAttempt);
          this.save(id, { state: 'rolled_back', phase: 'completed', result, error_code: 'new_configuration_failed' });
        } catch (recoveryError) {
          this.save(id, { state: 'unknown', phase: 'unknown', error_code: recoveryError.message === 'rollback_conflict' ? 'rollback_conflict' : 'recovery_unconfirmed' });
        }
      } else {
        this.save(id, { state: 'failed', phase: 'failed', error_code: ['unsupported_version', 'download_failed', 'candidate_invalid', 'baseline_changed', 'baseline_unverified'].includes(error.message) ? error.message : 'operation_failed' });
      }
    } finally {
      // Candidate/raw backups contain proxy credentials and remain only in root-private state.
      try { fs.unlinkSync(path.join(directory, 'builder.sh')); } catch { /* private temporary */ }
    }
  }
  async dispatch(action, id) {
    if (action === 'snapshot') return this.snapshot();
    if (action === 'fixed-ports') return this.fixedPorts();
    if (action === 'start-hot') {
      if (this.c.update_mode !== 'catalog_hot_reload') throw new Error('configuration_invalid');
      return this.start(id);
    }
    if (action === 'start') return this.start(id);
    if (action === 'operation') return this.operation(id);
    throw new Error('configuration_invalid');
  }
}

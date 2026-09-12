#!/usr/bin/env node
// Shared apply/recovery transaction behind both existing shell entry points.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';

const require = createRequire(import.meta.url);
const env = process.env;
const work = path.resolve(env.WORK_DIR || '/etc/local-socks');
const cache = path.resolve(env.CACHE_DIR || path.join(work, 'cache/node-health'));
const configPath = path.resolve(env.CONFIG_PATH || path.join(work, 'config.yaml'));
const exportDir = path.resolve(env.EXPORT_DIR || '/root/local-socks');
const core = path.resolve(env.MIHOMO_BIN || path.join(work, 'bin/mihomo-local-socks'));
const service = env.SERVICE_SCRIPT || '/etc/init.d/local-socks';
const converterPath = path.resolve(env.STABLE_CONVERTER || path.join(work, 'convert-any-proxy-to-local-socks-stable.js'));
let converter, yaml;
try {
  converter = require(converterPath);
  if (converter.CONSUMER_CONTRACT !== 'local-socks-explicit-v1') throw new Error('incompatible converter');
  yaml = require(env.JS_YAML_PATH ? path.resolve(env.JS_YAML_PATH) : 'js-yaml');
} catch {
  process.stderr.write('node-health apply: dependency_invalid\n');
  process.exit(1);
}
const appliedPath = path.join(cache, 'applied.json');
const pendingPath = path.join(cache, 'pending.json');
const generationRoot = path.join(cache, 'generations');
const backoffPath = path.join(cache, 'backoff.json');
let currentPhase = 'startup';
function failureCode(error) {
  const codes = {
    'inventory differs from target mapping': 'inventory_mismatch',
    'mapping changed before apply': 'mapping_changed',
    'mapping changed during download': 'mapping_changed',
    'mapping timestamp is stale or invalid': 'mapping_stale',
    'unapproved mapping namespace': 'source_unapproved',
    'unapproved mapping server_instance_id': 'source_unapproved',
    'unapproved mapping port_plan_version': 'port_plan_unapproved',
    'unapproved runtime profile': 'profile_unapproved',
    'initial port binding changes require approved mapping version': 'initial_mapping_unapproved',
    'runtime rejected candidate configuration': 'candidate_invalid',
    'new runtime is not ready': 'runtime_not_ready',
    'local runtime recovery incomplete; previous generation retained': 'recovery_incomplete',
    'final export directory overlaps runtime dependencies': 'export_dependency_overlap',
    'mapping or inventory download failed': 'download_failed',
    'mapping digest mismatch': 'mapping_invalid',
    'inventory fingerprint mismatch': 'mapping_invalid',
    'unsupported mapping contract or purpose': 'contract_unsupported',
    'application interrupted': 'interrupted',
  };
  return Object.hasOwn(codes, error?.message) ? codes[error.message] : 'operation_failed';
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let interruptionRequested = false;
let downloadChild = null;
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
  interruptionRequested = true;
  downloadChild?.kill('SIGTERM');
});
function checkInterrupted() { if (interruptionRequested) throw new Error('application interrupted'); }
const fileHash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const readJSON = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const readConfig = file => yaml.load(fs.readFileSync(file, 'utf8'));
const exists = file => fs.existsSync(file);
function syncDirectory(directory) {
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function atomicWrite(file, content, mode = 0o600) {
  const temporary = `${file}.new.${crypto.randomUUID()}`;
  const fd = fs.openSync(temporary, 'wx', mode);
  try { fs.writeFileSync(fd, content); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
  syncDirectory(path.dirname(file));
}
const writeJSON = (file, value) => atomicWrite(file, `${JSON.stringify(value, null, 2)}\n`);
function command(file, args) {
  const result = spawnSync(file, args, { stdio: 'ignore', timeout: 30000 });
  return !result.error && result.status === 0;
}
function realPath(file) {
  const resolved = path.resolve(file);
  if (exists(resolved)) return fs.realpathSync(resolved);
  return path.join(realPath(path.dirname(resolved)), path.basename(resolved));
}
function validatePaths() {
  const target = realPath(exportDir);
  if (target === path.parse(target).root) throw new Error('dedicated export directory required');
  const inputs = process.argv[2] === 'apply' ? process.argv.slice(3, 5) : [];
  const dependencies = [work, cache, configPath, core, converterPath, service, process.argv[1], process.execPath,
    env.RUNTIME_PROFILE_PATH, env.SERVICE_PID_FILE, env.NODE_HEALTH_ENV_FILE, ...inputs,
    env.JS_YAML_PATH, ...String(env.NODE_PATH || '').split(path.delimiter)].filter(Boolean);
  for (const dependency of dependencies) {
    const value = realPath(dependency);
    if (value === target || value.startsWith(`${target}${path.sep}`) || target.startsWith(`${value}${path.sep}`)) {
      throw new Error('final export directory overlaps runtime dependencies');
    }
  }
  if (exists(exportDir) && fs.lstatSync(exportDir).isSymbolicLink()) throw new Error('export directory must not itself be a symlink');
}
function hashExports(directory) {
  if (!exists(directory)) return null;
  const files = {};
  for (const name of fs.readdirSync(directory).sort()) {
    const file = path.join(directory, name);
    if (!fs.lstatSync(file).isFile()) throw new Error('exports must contain regular files only');
    files[name] = fileHash(file);
  }
  return converter.digest(files);
}
function generation(id) {
  if (!/^[0-9a-f-]{36}$/.test(id || '')) throw new Error('invalid generation reference');
  return path.join(generationRoot, id);
}
function persistedCopy(source, target) {
  fs.copyFileSync(source, target);
  const stat = fs.statSync(source);
  fs.chmodSync(target, stat.mode & 0o777);
  const fd = fs.openSync(target, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function verifiedProcess(pid) {
  if (!Number.isInteger(pid) || pid <= 1) return null;
  try {
    const args = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
    const flag = args.indexOf('-f');
    if (flag < 0 || args[flag + 1] !== configPath || fileHash(`/proc/${pid}/exe`) !== fileHash(core)) return null;
    const started = processIdentity(pid);
    return started ? { pid, started } : null;
  } catch { return null; }
}
function serviceProcess() {
  const ubus = spawnSync('ubus', ['call', 'service', 'list', JSON.stringify({ name: env.SERVICE_NAME || 'local-socks' })],
    { encoding: 'utf8', timeout: 5000 });
  if (!ubus.error && ubus.status === 0) {
    try {
      const value = JSON.parse(ubus.stdout)[env.SERVICE_NAME || 'local-socks'];
      for (const instance of Object.values(value?.instances || {})) {
        const verified = instance.running === true && verifiedProcess(instance.pid);
        if (verified) return verified;
      }
    } catch { /* A configured PID file can provide the same process proof. */ }
  }
  if (env.SERVICE_PID_FILE) {
    try { return verifiedProcess(Number(fs.readFileSync(env.SERVICE_PID_FILE, 'utf8').trim())); } catch { return null; }
  }
  return null;
}
function checkSocket(listener, empty = false) {
  return new Promise(resolve => {
    const configured = listener.listen;
    const host = configured && !['0.0.0.0', '::', '*'].includes(configured) ? configured : '127.0.0.1';
    const socket = net.createConnection({ host, port: listener.port });
    let done = false;
    const finish = ok => { if (!done) { done = true; socket.destroy(); resolve(ok); } };
    socket.setTimeout(Number(env.LISTENER_CONNECT_TIMEOUT_MS || 1500));
    socket.once('connect', () => {
      if (empty) finish(false);
      else socket.write(Buffer.from([5, 2, 0, 2]));
    });
    let response = Buffer.alloc(0);
    socket.on('data', chunk => {
      response = Buffer.concat([response, chunk]);
      if (response.length >= 2) finish(response[0] === 5 && [0, 2].includes(response[1]));
    });
    socket.once('timeout', () => finish(false));
    socket.once('error', error => finish(empty && error.code === 'ECONNREFUSED'));
    socket.once('end', () => finish(false));
  });
}
async function runtimeReady(config, map = null) {
  if (!serviceProcess() || !Array.isArray(config.listeners)) return false;
  const checks = config.listeners.map(listener => [listener, false]);
  if (map) for (const binding of map.bindings) {
    if (binding.entry_id === null) checks.push([{ port: binding.port }, true]);
  }
  let cursor = 0, ok = true;
  const concurrency = Number(env.LISTENER_CHECK_CONCURRENCY || 64);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 512) throw new Error('invalid listener check concurrency');
  await Promise.all(Array.from({ length: Math.min(concurrency, checks.length) }, async () => {
    while (cursor < checks.length) {
      const [listener, empty] = checks[cursor++];
      if (!(await checkSocket(listener, empty))) ok = false;
    }
  }));
  return ok;
}
async function waitReady(config, map = null, previousProcess = null) {
  const attempts = Number(env.READINESS_ATTEMPTS || 5);
  if (!Number.isInteger(attempts) || attempts < 1 || attempts > 60) throw new Error('invalid readiness attempts');
  for (let i = 0; i < attempts; i += 1) {
    const currentProcess = serviceProcess();
    const replaced = !previousProcess || (currentProcess &&
      (currentProcess.pid !== previousProcess.pid || currentProcess.started !== previousProcess.started));
    if (replaced && await runtimeReady(config, map)) return true;
    await sleep(Number(env.READINESS_DELAY_SECONDS ?? 2) * 1000);
  }
  return false;
}
async function restartAndWait(config, map = null) {
  const previous = serviceProcess();
  return command(service, ['restart']) && await waitReady(config, map, previous);
}
function approvals() {
  return { namespace: env.APPROVED_NAMESPACE, serverInstanceId: env.APPROVED_SERVER_INSTANCE_ID,
    portPlanVersion: env.APPROVED_PORT_PLAN_VERSION, maxAgeSeconds: Number(env.MAP_MAX_AGE_SECONDS || 129600) };
}
function copyExports(source, destination) {
  fs.mkdirSync(destination, { mode: 0o700 });
  for (const name of fs.readdirSync(source)) persistedCopy(path.join(source, name), path.join(destination, name));
  syncDirectory(destination);
}
function exportFiles(manifest, map) {
  const host = String(env.ADVERTISE_HOST || '').trim();
  if (!host || /[\s/{}]/u.test(host)) throw new Error('valid advertise host required');
  const address = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const files = {}, all = [], plain = [];
  for (const region of map.regions) {
    const entries = manifest.filter(entry => entry.region === region.id).sort((a, b) => a.port - b.port);
    const lines = entries.map(entry => `socks5://${address}:${entry.port}{${entry.name.replace(/[\r\n]+/g, ' ').trim()}}`);
    files[`${region.id}.txt`] = lines.length ? `${lines.join('\n')}\n` : '';
    all.push(...lines); plain.push(...entries.map(entry => `socks5://${address}:${entry.port}`));
  }
  files['all.txt'] = all.length ? `${all.join('\n')}\n` : '';
  files['all-plain.txt'] = plain.length ? `${plain.join('\n')}\n` : '';
  files['README.txt'] = `Verified applied mapping ${map.mapping_version}\nRanking ${map.ranking_version}\n`;
  return files;
}
function receiptFor(id, kind, map = null, rendered = null) {
  const directory = generation(id);
  return { schema_version: 1, kind, generation_id: id,
    config_sha256: fileHash(path.join(directory, 'config.yaml')), core_sha256: fileHash(path.join(directory, 'core')),
    exports_hash: hashExports(path.join(directory, 'exports')),
    runtime_config_hash: rendered?.runtime_config_hash || converter.digest(readConfig(path.join(directory, 'config.yaml'))),
    manifest_hash: rendered?.manifest_hash || null, consumer_contract: map?.consumer_contract || null,
    mapping_version: map?.mapping_version || null, ranking_version: map?.ranking_version || null,
    inventory_fingerprint: map?.inventory_fingerprint || null, namespace: map?.namespace || null,
    server_instance_id: map?.server_instance_id || null, port_plan_version: map?.port_plan_version || null,
    applied_at: new Date().toISOString() };
}
async function ensureBaseline() {
  currentPhase = 'baseline';
  if (exists(appliedPath)) return readJSON(appliedPath);
  if (!exists(configPath) || !exists(core)) throw new Error('verified legacy runtime is required for initial migration');
  const config = readConfig(configPath);
  converter.runtimeProjection(config);
  if (!command(core, ['-d', work, '-t', '-f', configPath]) || !(await runtimeReady(config))) throw new Error('legacy runtime baseline is not ready');
  const id = crypto.randomUUID(), directory = generation(id);
  fs.mkdirSync(directory, { mode: 0o700 });
  persistedCopy(configPath, path.join(directory, 'config.yaml'));
  persistedCopy(core, path.join(directory, 'core'));
  if (exists(exportDir)) copyExports(exportDir, path.join(directory, 'exports'));
  const stat = fs.statSync(configPath);
  writeJSON(path.join(directory, 'permissions.json'), { mode: stat.mode & 0o777, uid: stat.uid, gid: stat.gid });
  const receipt = receiptFor(id, 'legacy-baseline');
  writeJSON(path.join(directory, 'baseline.json'), receipt);
  syncDirectory(generationRoot);
  writeJSON(appliedPath, receipt);
  return receipt;
}
function replaceConfig(source, permissions) {
  atomicWrite(configPath, fs.readFileSync(source), permissions.mode);
  fs.chownSync(configPath, permissions.uid, permissions.gid);
}
function publishExports(source) {
  const stage = `${exportDir}.new.${crypto.randomUUID()}`, backup = `${exportDir}.previous.${crypto.randomUUID()}`;
  let moved = false;
  try {
    if (exists(source)) copyExports(source, stage);
    if (exists(exportDir)) { fs.renameSync(exportDir, backup); moved = true; }
    if (exists(stage)) fs.renameSync(stage, exportDir);
    syncDirectory(path.dirname(exportDir));
  } catch (error) {
    if (moved && !exists(exportDir)) fs.renameSync(backup, exportDir);
    throw error;
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
    if (exists(exportDir)) fs.rmSync(backup, { recursive: true, force: true });
  }
}
async function restore(receipt, forceRestart = false) {
  currentPhase = 'recover';
  const directory = generation(receipt.generation_id), snapshot = path.join(directory, 'config.yaml');
  if (fileHash(snapshot) !== receipt.config_sha256 || fileHash(path.join(directory, 'core')) !== receipt.core_sha256) throw new Error('recovery generation is corrupt');
  let failed = false;
  const changed = !exists(configPath) || fileHash(configPath) !== receipt.config_sha256 || !exists(core) || fileHash(core) !== receipt.core_sha256;
  try {
    replaceConfig(snapshot, readJSON(path.join(directory, 'permissions.json')));
    if (!exists(core) || fileHash(core) !== receipt.core_sha256) atomicWrite(core, fs.readFileSync(path.join(directory, 'core')), 0o755);
  } catch { failed = true; }
  try { publishExports(path.join(directory, 'exports')); } catch { failed = true; }
  const config = readConfig(snapshot);
  const map = exists(path.join(directory, 'map.json')) ? readJSON(path.join(directory, 'map.json')) : null;
  if (changed || forceRestart || !(await runtimeReady(config, map))) {
    if (!(await restartAndWait(config, map))) failed = true;
  }
  if (failed) throw new Error('local runtime recovery incomplete; previous generation retained');
}
async function recoverLocal() {
  currentPhase = 'recover';
  if (exists(pendingPath)) {
    const pending = readJSON(pendingPath);
    if (!exists(appliedPath)) throw new Error('pending apply has no recovery receipt');
    const receipt = readJSON(appliedPath);
    // applied.json is the only commit selector, including the post-commit crash window.
    if (receipt.generation_id !== pending.next_generation_id && receipt.generation_id !== pending.previous_generation_id) throw new Error('pending apply does not match commit selector');
    await restore(receipt, receipt.generation_id === pending.previous_generation_id);
    fs.unlinkSync(pendingPath); syncDirectory(cache);
  }
  if (!exists(appliedPath)) return false;
  const receipt = readJSON(appliedPath);
  const directory = generation(receipt.generation_id);
  const config = readConfig(path.join(directory, 'config.yaml'));
  const map = exists(path.join(directory, 'map.json')) ? readJSON(path.join(directory, 'map.json')) : null;
  const coherent = exists(configPath) && fileHash(configPath) === receipt.config_sha256 && exists(core) &&
    fileHash(core) === receipt.core_sha256 && hashExports(exportDir) === receipt.exports_hash;
  if (!coherent || !(await runtimeReady(config, map))) { await restore(receipt); return true; }
  return false;
}
async function apply(sourcePath, mapPath, expectedVersion) {
  await recoverLocal();
  checkInterrupted();
  currentPhase = 'validate-target';
  const map = readJSON(mapPath);
  if (map.mapping_version !== expectedVersion) throw new Error('mapping changed before apply');
  const profilePath = env.RUNTIME_PROFILE_PATH;
  if (!profilePath) throw new Error('approved runtime profile required');
  const rendered = converter.convertConfig(readConfig(sourcePath), map, { ...approvals(),
    runtimeProfile: readConfig(profilePath), runtimeProfileHash: env.APPROVED_RUNTIME_PROFILE_HASH,
    previousConfig: exists(configPath) ? readConfig(configPath) : undefined });
  const outputFiles = exportFiles(rendered.manifest, map);
  const expectedExportsHash = converter.digest(Object.fromEntries(Object.entries(outputFiles)
    .map(([name, content]) => [name, converter.sha256Hex(content)])));
  if (exists(appliedPath)) {
    const receipt = readJSON(appliedPath);
    if (receipt.kind === 'managed' && receipt.mapping_version === map.mapping_version &&
        receipt.runtime_config_hash === rendered.runtime_config_hash && receipt.manifest_hash === rendered.manifest_hash &&
        receipt.exports_hash === expectedExportsHash) return receipt;
  }
  const previous = await ensureBaseline();
  if (previous.kind === 'legacy-baseline' &&
      converter.canonicalJson(converter.runtimeProjection(readConfig(configPath))) !== converter.canonicalJson(converter.runtimeProjection(rendered.config)) &&
      env.APPROVED_INITIAL_MAPPING_VERSION !== map.mapping_version) {
    throw new Error('initial port binding changes require approved mapping version');
  }
  const id = crypto.randomUUID(), directory = generation(id);
  fs.mkdirSync(directory, { mode: 0o700 });
  const candidate = path.join(directory, 'config.yaml');
  currentPhase = 'validate-config';
  atomicWrite(candidate, yaml.dump(rendered.config, { noRefs: true, lineWidth: -1 }));
  if (!command(core, ['-d', work, '-t', '-f', candidate])) throw new Error('runtime rejected candidate configuration');
  persistedCopy(core, path.join(directory, 'core'));
  const oldStat = fs.statSync(configPath);
  const permissions = { mode: Number.parseInt(env.CONFIG_MODE || '0640', 8), uid: oldStat.uid, gid: oldStat.gid };
  writeJSON(path.join(directory, 'permissions.json'), permissions);
  writeJSON(path.join(directory, 'map.json'), map);
  writeJSON(path.join(directory, 'manifest.json'), rendered.manifest);
  const exports = path.join(directory, 'exports');
  fs.mkdirSync(exports, { mode: 0o700 });
  for (const [name, contents] of Object.entries(outputFiles)) atomicWrite(path.join(exports, name), contents);
  const unchanged = converter.digest(readConfig(configPath)) === rendered.runtime_config_hash && fileHash(core) === previous.core_sha256;
  // Preserve exact bytes on semantic no-ops, including a YAML formatting difference.
  if (unchanged) persistedCopy(configPath, candidate);
  const next = receiptFor(id, 'managed', map, rendered);
  syncDirectory(directory);
  syncDirectory(generationRoot);
  checkInterrupted();
  writeJSON(pendingPath, { schema_version: 1, previous_generation_id: previous.generation_id, next_generation_id: id });
  try {
    currentPhase = 'replace-config';
    if (!unchanged) replaceConfig(candidate, permissions);
    checkInterrupted();
    if (!unchanged || !(await runtimeReady(rendered.config, map))) {
      currentPhase = 'restart';
      if (!(await restartAndWait(rendered.config, map))) throw new Error('new runtime is not ready');
    }
    checkInterrupted();
    if (fileHash(configPath) !== next.config_sha256 || fileHash(core) !== next.core_sha256) throw new Error('runtime files changed during apply');
    currentPhase = 'exports';
    publishExports(exports);
    if (hashExports(exportDir) !== next.exports_hash) throw new Error('export publication mismatch');
    next.applied_at = new Date().toISOString();
    currentPhase = 'commit';
    writeJSON(appliedPath, next);
  } catch (error) {
    const failedPhase = currentPhase;
    const committed = readJSON(appliedPath);
    await restore(committed, !unchanged);
    if (exists(pendingPath)) { fs.unlinkSync(pendingPath); syncDirectory(cache); }
    currentPhase = failedPhase;
    throw error;
  }
  // These projections do not change the committed application outcome.
  try {
    fs.unlinkSync(pendingPath); syncDirectory(cache);
    atomicWrite(path.join(cache, 'applied.version'), `${map.mapping_version}\n`);
    atomicWrite(path.join(cache, 'applied.sha256'), `${next.config_sha256}\n`);
    for (const name of fs.readdirSync(generationRoot)) {
      if (name !== id && name !== previous.generation_id && /^[0-9a-f-]{36}$/.test(name) &&
          !exists(path.join(generationRoot, name, 'baseline.json'))) {
        fs.rmSync(path.join(generationRoot, name), { recursive: true, force: true });
      }
    }
  } catch { process.stderr.write('node-health apply: committed; derived cleanup pending\n'); }
  return next;
}
async function download(url, destination) {
  if (!/^https?:\/\//i.test(url)) throw new Error('HTTP subscription URL required');
  await new Promise((resolve, reject) => {
    const child = spawn('curl', ['--fail', '--silent', '--location', '--proto', '=http,https', '--proto-redir', '=http,https',
      '--header', 'Cache-Control: no-cache', '--header', 'Pragma: no-cache',
      '--connect-timeout', env.CURL_CONNECT_TIMEOUT || '10', '--max-time', env.CURL_MAX_TIME || '120', '--output', destination, url],
    { stdio: 'ignore' });
    downloadChild = child;
    child.once('error', () => reject(new Error('download command unavailable')));
    child.once('exit', code => {
      downloadChild = null;
      code === 0 ? resolve() : reject(new Error('mapping or inventory download failed'));
    });
  });
}
async function poll() {
  await recoverLocal();
  if (exists(backoffPath) && readJSON(backoffPath).retry_after > Date.now()) { currentPhase = 'backoff'; return; }
  checkInterrupted();
  const stage = fs.mkdtempSync(path.join(cache, 'download.'));
  try {
    const first = path.join(stage, 'first.json'), final = path.join(stage, 'map.json'), source = path.join(stage, 'inventory.yaml');
    currentPhase = 'download-map';
    await download(env.RANKING_URL || '', first);
    currentPhase = 'validate-target';
    const mapA = converter.validateMapping(readJSON(first), approvals());
    const url = new URL(env.SOURCE_URL || '');
    if (url.hash || /\/download\/collection\/healthy\/?$/.test(url.pathname) ||
        url.searchParams.get('target') !== 'ClashMeta' || url.searchParams.get('noCache') !== 'true') throw new Error('complete uncached ClashMeta inventory URL required');
    url.searchParams.set('_node_health_version', mapA.mapping_version);
    currentPhase = 'download-inventory';
    await download(url.toString(), source);
    currentPhase = 'download-map';
    await download(env.RANKING_URL, final);
    const mapB = converter.validateMapping(readJSON(final), approvals());
    if (mapA.mapping_version !== mapB.mapping_version) throw new Error('mapping changed during download');
    await apply(source, final, mapB.mapping_version);
    fs.rmSync(backoffPath, { force: true });
  } catch (error) {
    const previous = exists(backoffPath) ? readJSON(backoffPath).attempts : 0;
    const attempts = Number.isInteger(previous) ? previous + 1 : 1;
    const delay = Math.min(Number(env.BACKOFF_MAX_SECONDS || 21600), Number(env.BACKOFF_BASE_SECONDS || 900) * 2 ** Math.min(attempts - 1, 20));
    writeJSON(backoffPath, { attempts, retry_after: Date.now() + delay * 1000, reason: failureCode(error) });
    throw error;
  } finally { fs.rmSync(stage, { recursive: true, force: true }); }
}

function processIdentity(pid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19];
  } catch { return null; }
}
async function withLock(action) {
  fs.mkdirSync(cache, { recursive: true, mode: 0o700 });
  fs.mkdirSync(generationRoot, { recursive: true, mode: 0o700 });
  // The shell entry points hold a kernel flock on an inherited descriptor.
  // SIGKILL releases it without a stale owner file or an unsafe reaper race.
  if (env.NODE_HEALTH_LOCK_FD !== '9' ||
      fs.realpathSync('/proc/self/fd/9') !== realPath(path.join(cache, 'apply.lock'))) {
    throw new Error('use the locking shell entry point');
  }
  await action();
}
try {
  await withLock(async () => {
    validatePaths();
    const [action, source, map, version] = process.argv.slice(2);
    if (action === 'apply' && source && map && version) await apply(source, map, version);
    else if (action === 'recover') await recoverLocal();
    else if (action === 'check') await poll();
    else throw new Error('unsupported controller command');
  });
  if (currentPhase !== 'backoff') {
    try { fs.rmSync(path.join(cache, 'last-error.json'), { force: true }); } catch { /* Diagnostic cleanup is not the commit selector. */ }
  }
} catch (error) {
  const failure = { code: failureCode(error), phase: currentPhase,
    diagnostic_id: crypto.randomUUID(), observed_at: new Date().toISOString() };
  try { writeJSON(path.join(cache, 'last-error.json'), failure); } catch { /* The bounded stderr record remains available. */ }
  process.stderr.write(`node-health apply: ${failure.code} phase=${failure.phase} diagnostic=${failure.diagnostic_id}\n`);
  process.exitCode = 1;
}

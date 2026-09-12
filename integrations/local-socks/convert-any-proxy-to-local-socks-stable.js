'use strict';
// Node-only renderer for Python's explicit mapping. It never allocates ports.
const crypto = require('node:crypto');
const CONSUMER_CONTRACT = 'local-socks-explicit-v1';
const REGION_KEYS = ['hong-kong', 'taiwan', 'japan', 'singapore', 'united-states',
  'south-korea', 'united-kingdom', 'germany', 'france', 'canada', 'australia', 'other'];
const REGION_PORT_BLOCKS = REGION_KEYS.map(key => ({ key, unlimited: key === 'other' }));
const HEX = /^[0-9a-f]{64}$/;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const clone = value => JSON.parse(JSON.stringify(value));
function compareCodePoints(a, b) {
  const left = Array.from(a), right = Array.from(b);
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    const delta = left[i].codePointAt(0) - right[i].codePointAt(0);
    if (delta) return delta;
  }
  return left.length - right.length;
}
function canonicalJson(value, topLevel = false) {
  if (Array.isArray(value)) return `[${value.map(item => canonicalJson(item)).join(',')}]`;
  if (record(value)) {
    const keys = Object.keys(value).filter(key => value[key] !== undefined &&
      !(topLevel && (key === 'name' || key.startsWith('_') || (key === 'port' && value.ports))));
    return `{${keys.sort(compareCodePoints).map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}
const sha256Hex = value => crypto.createHash('sha256').update(value, 'utf8').digest('hex');
const digest = value => `sha256:${sha256Hex(canonicalJson(value))}`;
function nodeKey(proxy) {
  if (!record(proxy)) throw new Error('proxy must be an object');
  return sha256Hex(canonicalJson(proxy, true));
}
const normalizeIdentityText = value => String(value || '').normalize('NFKC').trim().replace(/\s+/gu, ' ').toLowerCase();
const originalName = proxy => String(proxy._nh_original_name || proxy._original_name || proxy.name || '').trim().replace(/\s+/gu, ' ');
const sourceId = proxy => normalizeIdentityText(proxy._nh_source_id || proxy._source_id);
const aliasEntryId = (key, source, original, name, ordinal = 1) => sha256Hex(JSON.stringify([key, source, original, name, ordinal]));

function inventoryEntries(proxies) {
  if (!Array.isArray(proxies) || !proxies.length) throw new Error('inventory has no proxies');
  const counts = new Map();
  return proxies.map(proxy => {
    if (!record(proxy) || typeof proxy.name !== 'string' || !proxy.name.trim()) throw new Error('invalid inventory proxy');
    const key = nodeKey(proxy), source = sourceId(proxy), original = originalName(proxy), name = proxy.name.trim();
    const tuple = JSON.stringify([key, source, original, name]);
    const ordinal = (counts.get(tuple) || 0) + 1;
    counts.set(tuple, ordinal);
    return { entry_id: aliasEntryId(key, source, original, name, ordinal), node_key: key,
      source_id: source, original_name: original, name, duplicate_ordinal: ordinal, proxy };
  });
}
function inventoryFingerprint(entries) {
  return digest(entries.map(entry => Object.fromEntries(
    ['entry_id', 'node_key', 'name', 'source_id', 'original_name', 'duplicate_ordinal'].map(key => [key, entry[key]]),
  )).sort((a, b) => compareCodePoints(a.entry_id, b.entry_id)));
}
function mappingDigest(map) {
  return digest(Object.fromEntries(Object.entries(map).filter(([key]) =>
    !['mapping_version', 'generated_at', 'ranking_version', 'application_status'].includes(key))));
}
const defaultRegions = () => REGION_KEYS.map((id, i) => ({ id, base: 62000 + i * 200,
  capacity: id === 'other' ? 1336 : 200, stable_count: id === 'other' ? 0 : 3 }));

function validateMapping(map, approvals = {}) {
  if (!record(map) || map.schema_version !== 1 || map.consumer_contract !== CONSUMER_CONTRACT ||
      map.purpose !== 'production' || map.application_status !== 'target-only') throw new Error('unsupported mapping contract or purpose');
  for (const [field, expected] of [['namespace', approvals.namespace], ['server_instance_id', approvals.serverInstanceId],
    ['port_plan_version', approvals.portPlanVersion]]) {
    if (typeof expected !== 'string' || !expected || map[field] !== expected) throw new Error(`unapproved mapping ${field}`);
  }
  if (!Array.isArray(map.regions) || canonicalJson(map.regions) !== canonicalJson(defaultRegions()) ||
      digest(map.regions) !== map.port_plan_version) throw new Error('invalid port plan');
  if (mappingDigest(map) !== map.mapping_version) throw new Error('mapping digest mismatch');
  if (typeof map.ranking_version !== 'string' || !map.ranking_version) throw new Error('ranking version required');
  const age = (Number(approvals.nowMs ?? Date.now()) - Date.parse(map.generated_at)) / 1000;
  const maximumAge = Number(approvals.maxAgeSeconds ?? 36 * 3600);
  if (!Number.isFinite(age) || age < -300 || !Number.isFinite(maximumAge) || maximumAge <= 0 || age > maximumAge) throw new Error('mapping timestamp is stale or invalid');
  if (!Array.isArray(map.entries) || !map.entries.length || !Array.isArray(map.bindings)) throw new Error('mapping entries required');
  const entries = new Map();
  for (const entry of map.entries) {
    if (!record(entry) || !HEX.test(entry.entry_id) || !HEX.test(entry.node_key) || entries.has(entry.entry_id) ||
        !REGION_KEYS.includes(entry.region) || typeof entry.name !== 'string' || !entry.name.trim() ||
        typeof entry.source_id !== 'string' || typeof entry.original_name !== 'string' ||
        !Number.isInteger(entry.duplicate_ordinal) || entry.duplicate_ordinal < 1 ||
        aliasEntryId(entry.node_key, entry.source_id, entry.original_name, entry.name, entry.duplicate_ordinal) !== entry.entry_id) throw new Error('invalid or repeated mapping entry');
    entries.set(entry.entry_id, entry);
  }
  if (inventoryFingerprint(map.entries) !== map.inventory_fingerprint) throw new Error('inventory fingerprint mismatch');
  const ports = new Set(), used = new Set(), stableKeys = new Set(), slots = new Set();
  const dynamicIndexes = new Map(REGION_KEYS.map(key => [key, []]));
  for (const binding of map.bindings) {
    const region = map.regions.find(value => value.id === binding.region);
    if (!region || !Number.isInteger(binding.port) || binding.port < region.base ||
        binding.port >= region.base + region.capacity || ports.has(binding.port)) throw new Error('invalid or conflicting port');
    ports.add(binding.port);
    if (binding.role === 'stable') {
      if (!Number.isInteger(binding.slot) || binding.slot < 1 || binding.slot > region.stable_count ||
          binding.port !== region.base + binding.slot - 1) throw new Error('invalid stable port');
      slots.add(`${region.id}/${binding.slot}`);
      if (binding.entry_id === null && binding.node_key === null) continue;
      if (stableKeys.has(binding.node_key)) throw new Error('one connection occupies multiple stable slots');
      stableKeys.add(binding.node_key);
    } else if (binding.role === 'dynamic') {
      if (!Number.isInteger(binding.dynamic_index) || binding.dynamic_index < 1 ||
          binding.port !== region.base + region.stable_count + binding.dynamic_index - 1) throw new Error('invalid dynamic port');
      dynamicIndexes.get(region.id).push(binding.dynamic_index);
    } else throw new Error('invalid binding role');
    const entry = entries.get(binding.entry_id);
    if (!entry || entry.node_key !== binding.node_key || entry.region !== binding.region || used.has(entry.entry_id)) throw new Error('incomplete or mismatched instance binding');
    used.add(entry.entry_id);
  }
  for (const region of map.regions) {
    for (let slot = 1; slot <= region.stable_count; slot += 1) {
      if (!slots.has(`${region.id}/${slot}`)) throw new Error('explicit empty slot required');
    }
    const indexes = dynamicIndexes.get(region.id).sort((a, b) => a - b);
    if (indexes.some((index, i) => index !== i + 1)) throw new Error('noncontiguous dynamic mapping');
  }
  if (used.size !== entries.size) throw new Error('mapping omits inventory instances');
  return map;
}

function runtimeShell(profile) {
  if (!record(profile)) throw new Error('approved runtime profile required');
  const shell = clone(profile);
  delete shell.proxies; delete shell.listeners;
  return shell;
}
function listenerOptions(listener) {
  const value = clone(listener);
  delete value.name; delete value.port; delete value.proxy;
  if (value.type !== 'mixed') throw new Error('approved listeners must be mixed');
  return value;
}
const runtimeProfileHash = profile => digest({ shell: runtimeShell(profile),
  listeners: (profile.listeners || []).map(listener => ({ port: listener.port, options: listenerOptions(listener) })) });
function optionsForPort(profile, port) {
  const listeners = profile.listeners || [];
  const existing = listeners.find(listener => listener.port === port);
  if (existing) return listenerOptions(existing);
  const options = listeners.map(listenerOptions);
  if (options.some(value => canonicalJson(value) !== canonicalJson(options[0]))) throw new Error('new listener needs an explicitly reviewed profile');
  return options[0] || { type: 'mixed' };
}
function inPortRange(port, ranges) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  return String(ranges).split(',').some(part => {
    const match = part.trim().match(/^(\d+)(?:[-:](\d+))?$/);
    return match && port >= Number(match[1]) && port <= Number(match[2] || match[1]);
  });
}
function proxyForRuntime(proxy, previous) {
  const value = clone(proxy);
  for (const key of Object.keys(value)) if (key.startsWith('_')) delete value[key];
  if (value['dialer-proxy']) throw new Error('proxy dependency requires an explicit reviewed adapter');
  if (value.ports) {
    if (value.type !== 'hysteria2') throw new Error('unsupported port-hopping protocol');
    if (previous && inPortRange(previous.port, value.ports)) value.port = previous.port;
    else if (!inPortRange(value.port, value.ports)) {
      const first = Number(String(value.ports).split(/[,:-]/)[0]);
      if (!inPortRange(first, value.ports)) throw new Error('invalid port-hopping range');
      value.port = first;
    }
  }
  value.name = `nh-${nodeKey(proxy)}`;
  return value;
}
function remapShellReferences(profile, shell, proxies) {
  const names = new Set(proxies.map(proxy => proxy.name));
  const oldNames = new Map((profile.proxies || []).map(proxy => [proxy.name, `nh-${nodeKey(proxy)}`]));
  const groups = new Set((shell['proxy-groups'] || []).map(group => group.name));
  const builtins = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL']);
  function target(name) {
    const next = oldNames.get(name) || name;
    if (!names.has(next) && !groups.has(next) && !builtins.has(next)) throw new Error('runtime profile contains an unresolved proxy reference');
    return next;
  }
  for (const group of shell['proxy-groups'] || []) {
    if (names.has(group.name)) throw new Error('runtime group name collision');
    if (group.proxies) group.proxies = group.proxies.map(target);
  }
  if (shell['sub-rules']) throw new Error('sub-rule references require a reviewed runtime profile');
  if (shell.rules) shell.rules = shell.rules.map(rule => {
    if (typeof rule !== 'string') throw new Error('unsupported runtime rule');
    const parts = rule.split(',');
    const index = parts.at(-1) === 'no-resolve' ? parts.length - 2 : parts.length - 1;
    parts[index] = target(parts[index]);
    return parts.join(',');
  });
}
function runtimeProjection(config) {
  if (!record(config) || !Array.isArray(config.proxies) || !Array.isArray(config.listeners)) throw new Error('runtime config is incomplete');
  const proxies = new Map();
  for (const proxy of config.proxies) {
    if (proxies.has(proxy.name)) throw new Error('duplicate runtime proxy name');
    proxies.set(proxy.name, proxy);
  }
  const seen = new Set();
  return config.listeners.map(listener => {
    const proxy = proxies.get(listener.proxy);
    if (!proxy || !Number.isInteger(listener.port) || seen.has(listener.port)) throw new Error('unresolved runtime listener');
    seen.add(listener.port);
    return { port: listener.port, node_key: nodeKey(proxy), type: listener.type };
  }).sort((a, b) => a.port - b.port);
}
function verifyRuntimeBindings(config, map) {
  const expected = map.bindings.filter(binding => binding.entry_id !== null)
    .map(binding => ({ port: binding.port, node_key: binding.node_key, type: 'mixed' })).sort((a, b) => a.port - b.port);
  if (canonicalJson(runtimeProjection(config)) !== canonicalJson(expected)) throw new Error('runtime port-to-connection bindings differ from target');
}
function convertConfig(sourceConfig, map, options = {}) {
  validateMapping(map, options);
  const profile = options.runtimeProfile;
  if (!options.runtimeProfileHash || runtimeProfileHash(profile) !== options.runtimeProfileHash) throw new Error('unapproved runtime profile');
  const entries = inventoryEntries(sourceConfig && sourceConfig.proxies);
  if (inventoryFingerprint(entries) !== map.inventory_fingerprint) throw new Error('inventory differs from target mapping');
  const byId = new Map(entries.map(entry => [entry.entry_id, entry]));
  const previousByKey = new Map(((options.previousConfig || {}).proxies || []).map(proxy => [nodeKey(proxy), proxy]));
  const selected = new Map(), listeners = [], manifest = [];
  for (const binding of [...map.bindings].sort((a, b) => a.port - b.port)) {
    if (binding.entry_id === null) continue;
    const entry = byId.get(binding.entry_id);
    if (!entry || entry.node_key !== binding.node_key) throw new Error('inventory instance binding mismatch');
    if (!selected.has(entry.node_key)) selected.set(entry.node_key, proxyForRuntime(entry.proxy, previousByKey.get(entry.node_key)));
    listeners.push({ ...optionsForPort(profile, binding.port), name: `nh-listener-${binding.port}`,
      port: binding.port, proxy: selected.get(entry.node_key).name });
    manifest.push({ ...binding, name: entry.name });
  }
  const proxies = [...selected.values()].sort((a, b) => compareCodePoints(a.name, b.name));
  const shell = runtimeShell(profile);
  remapShellReferences(profile, shell, proxies);
  const config = { ...shell, proxies, listeners };
  verifyRuntimeBindings(config, map);
  return { config, manifest, runtime_config_hash: digest(config), manifest_hash: digest(manifest) };
}
module.exports = { CONSUMER_CONTRACT, REGION_PORT_BLOCKS, REGION_PORT_BLOCK_SIZE: 200, STABLE_SLOT_COUNT: 3,
  canonicalJson, sha256Hex, digest, nodeKey, normalizeIdentityText, originalName, sourceId, aliasEntryId,
  inventoryEntries, inventoryFingerprint, mappingDigest, defaultRegions, validateMapping, runtimeShell,
  runtimeProfileHash, inPortRange, runtimeProjection, verifyRuntimeBindings, convertConfig };

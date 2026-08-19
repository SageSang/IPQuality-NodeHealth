#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const [
  sourcePath,
  rankingPath,
  outputPath,
  rawStartPort,
  rawConverterPath,
  exportDirectory,
  advertiseHost,
] = process.argv.slice(2);

if (!sourcePath || !rankingPath || !outputPath || !rawConverterPath) {
  process.stderr.write(
    'usage: convert-ranking.mjs SOURCE_YAML CURRENT_JSON OUTPUT_YAML START_PORT CONVERTER_JS [EXPORT_DIR ADVERTISE_HOST]\n',
  );
  process.exit(2);
}

const startPort = Number(rawStartPort || 62000);
if (startPort !== 62000) {
  throw new Error('START_PORT must be exactly 62000 for the fixed regional port plan');
}

const converterPath = path.resolve(rawConverterPath);
if (exportDirectory) {
  const exportPath = path.resolve(exportDirectory);
  const dependencies = [
    ['converter', converterPath],
    ['candidate output', path.resolve(outputPath)],
    ...(process.env.CONFIG_PATH
      ? [['CONFIG_PATH', path.resolve(process.env.CONFIG_PATH)]]
      : []),
    ...(process.env.WORK_DIR ? [['WORK_DIR', path.resolve(process.env.WORK_DIR)]] : []),
    ...(process.env.CACHE_DIR ? [['CACHE_DIR', path.resolve(process.env.CACHE_DIR)]] : []),
    ...(process.env.JS_YAML_PATH
      ? [['JS_YAML_PATH', path.resolve(process.env.JS_YAML_PATH)]]
      : []),
    ...String(process.env.NODE_PATH || '')
      .split(path.delimiter)
      .filter(Boolean)
      .map((entry) => ['NODE_PATH', path.resolve(entry)]),
  ];
  const overlaps = (left, right) =>
    left === right || left.startsWith(`${right}${path.sep}`) || right.startsWith(`${left}${path.sep}`);
  for (const [label, dependencyPath] of dependencies) {
    if (overlaps(exportPath, dependencyPath)) {
      throw new Error(`${label} must not overlap EXPORT_DIR: ${dependencyPath}`);
    }
  }
}

const converter = require(converterPath);
const yaml = process.env.JS_YAML_PATH
  ? require(path.resolve(process.env.JS_YAML_PATH))
  : require('js-yaml');
const source = fs.readFileSync(sourcePath, 'utf8');
const current = JSON.parse(fs.readFileSync(rankingPath, 'utf8'));
const sourceConfig = yaml.load(source);

function keyFromEntry(value) {
  if (typeof value === 'string') return value;
  if (!value || typeof value !== 'object') return '';
  return String(value.node_key || value.nodeKey || value.key || '');
}

function stableSlotEntries(state) {
  const entries = [];
  for (const [regionKey, region] of Object.entries(state.regions || {})) {
    const slots = region && (region.stable_slots || region.stableSlots);
    if (!slots || typeof slots !== 'object' || Array.isArray(slots)) continue;
    for (const [slot, entry] of Object.entries(slots)) {
      const key = keyFromEntry(entry);
      if (key) entries.push({ region: regionKey, slot, key });
    }
  }
  return entries;
}

function retainMissingStableProxies(config, state) {
  const configProxies = Array.isArray(config && config.proxies) ? config.proxies : [];
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('source subscription is not a Clash proxy object');
  }
  if (!Array.isArray(config.proxies)) config.proxies = configProxies;

  const stableEntries = stableSlotEntries(state);
  if (stableEntries.length === 0 || !process.env.CONFIG_PATH) return [];

  const previousPath = path.resolve(process.env.CONFIG_PATH);
  if (!fs.existsSync(previousPath)) return [];

  let previousConfig;
  try {
    previousConfig = yaml.load(fs.readFileSync(previousPath, 'utf8'));
  } catch (error) {
    throw new Error(`previous local-socks config cannot be parsed: ${error.message}`);
  }
  const previousProxies = Array.isArray(previousConfig && previousConfig.proxies)
    ? previousConfig.proxies
    : [];
  const present = new Set();
  for (const proxy of config.proxies) {
    try {
      present.add(converter.nodeKey(proxy));
    } catch (_) {
      // The converter performs the authoritative source validation below.
    }
  }
  const previousByKey = new Map();
  for (const proxy of previousProxies) {
    try {
      const key = converter.nodeKey(proxy);
      if (!previousByKey.has(key)) previousByKey.set(key, proxy);
    } catch (_) {
      // Ignore malformed historical entries; they cannot safely be reused.
    }
  }

  const retained = [];
  for (const entry of stableEntries) {
    if (present.has(entry.key)) continue;
    const proxy = previousByKey.get(entry.key);
    if (!proxy) continue;
    config.proxies.push({ ...proxy });
    present.add(entry.key);
    retained.push(`${entry.region}/${entry.slot}`);
  }
  return retained;
}

const retainedStableSlots = retainMissingStableProxies(sourceConfig, current);
if (retainedStableSlots.length > 0) {
  process.stderr.write(
    `local-socks: retained previous definitions for stable slots ${retainedStableSlots.join(', ')}\n`,
  );
}
const outputConfig = converter.convertConfig(sourceConfig, current, startPort);
const dns = outputConfig && outputConfig.dns;
if (
  !dns ||
  dns.enable !== true ||
  dns.listen !== '127.0.0.1:11553' ||
  dns['enhanced-mode'] !== 'fake-ip' ||
  dns['fake-ip-range'] !== '198.18.0.1/16' ||
  !Array.isArray(dns['default-nameserver']) ||
  dns['default-nameserver'].length === 0 ||
  !Array.isArray(dns.nameserver) ||
  dns.nameserver.length === 0
) {
  throw new Error('converter output must preserve the independent fake-IP DNS configuration');
}
const allowedKeys = new Set();
for (const region of Object.values(current.regions || {})) {
  for (const entry of Object.values(region && region.stable_slots || {})) {
    const key = typeof entry === 'string' ? entry : entry && (entry.node_key || entry.nodeKey || entry.key);
    if (key) allowedKeys.add(String(key));
  }
  for (const entry of region && Array.isArray(region.ranked) ? region.ranked : []) {
    const key = typeof entry === 'string' ? entry : entry && (entry.node_key || entry.nodeKey || entry.key);
    if (key) allowedKeys.add(String(key));
  }
}
if (allowedKeys.size > 0 && (!Array.isArray(outputConfig.listeners) || outputConfig.listeners.length === 0)) {
  throw new Error(`inventory has zero matches for ${allowedKeys.size} allowed node(s)`);
}

const listenerPorts = new Set(
  (outputConfig.listeners || []).map((listener) => Number(listener && listener.port)),
);
const missingStableSlots = [];
for (const entry of stableSlotEntries(current)) {
  const regionIndex = converter.REGION_PORT_BLOCKS.findIndex(
    (region) => region.key === entry.region,
  );
  const region = converter.REGION_PORT_BLOCKS[regionIndex];
  if (!region || region.unlimited) continue;
  const slot = Number(entry.slot);
  const expectedPort = startPort + regionIndex * converter.REGION_PORT_BLOCK_SIZE + slot - 1;
  if (!listenerPorts.has(expectedPort)) {
    missingStableSlots.push(`${entry.region}/${entry.slot}:${expectedPort}`);
  }
}
if (missingStableSlots.length > 0) {
  throw new Error(
    `stable slot listeners are missing: ${missingStableSlots.join(', ')}`,
  );
}
const output = yaml.dump(outputConfig);

fs.writeFileSync(outputPath, output, { encoding: 'utf8', mode: 0o600 });

if (exportDirectory) {
  if (!advertiseHost) throw new Error('ADVERTISE_HOST is required with EXPORT_DIR');
  fs.mkdirSync(exportDirectory, { recursive: true, mode: 0o700 });

  const linesByRegion = new Map(
    converter.REGION_PORT_BLOCKS.map((region) => [region.key, []]),
  );
  const plainLinesByRegion = new Map(
    converter.REGION_PORT_BLOCKS.map((region) => [region.key, []]),
  );
  for (const listener of outputConfig.listeners || []) {
    const region = converter.REGION_PORT_BLOCKS.find((candidate) =>
      String(listener.name).startsWith(`mixed-${candidate.key}-`),
    );
    if (!region) continue;
    const name = String(listener.proxy).replace(/[\r\n]+/g, ' ').trim();
    const plainLine = `socks5://${advertiseHost}:${listener.port}`;
    linesByRegion
      .get(region.key)
      .push(`${plainLine}{${name}}`);
    plainLinesByRegion.get(region.key).push(plainLine);
  }

  for (const [region, lines] of linesByRegion) {
    const content = lines.length > 0 ? `${lines.join('\n')}\n` : '';
    fs.writeFileSync(path.join(exportDirectory, `${region}.txt`), content, {
      encoding: 'utf8',
      mode: 0o600,
    });
  }
  const allLines = [];
  const allPlainLines = [];
  for (const region of converter.REGION_PORT_BLOCKS) {
    allLines.push(...linesByRegion.get(region.key));
    allPlainLines.push(...plainLinesByRegion.get(region.key));
  }
  fs.writeFileSync(
    path.join(exportDirectory, 'all.txt'),
    allLines.length > 0 ? `${allLines.join('\n')}\n` : '',
    { encoding: 'utf8', mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(exportDirectory, 'all-plain.txt'),
    allPlainLines.length > 0 ? `${allPlainLines.join('\n')}\n` : '',
    { encoding: 'utf8', mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(exportDirectory, 'README.txt'),
    `Generated by node-health ranking ${current.version}\nStable slots keep fixed ports; dynamic nodes follow them.\n`,
    { encoding: 'utf8', mode: 0o600 },
  );
}

#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const [sourcePath, mappingPath, outputPath, startPort, converterPath, exportDirectory, advertiseHost] = process.argv.slice(2);

function realPath(value) {
  const resolved = path.resolve(value);
  return fs.existsSync(resolved) ? fs.realpathSync(resolved) : path.join(realPath(path.dirname(resolved)), path.basename(resolved));
}
try {
  if (!sourcePath || !mappingPath || !outputPath || !converterPath || Number(startPort) !== 62000) throw new Error('invalid arguments');
  const finalExport = process.env.EXPORT_DIR;
  if (exportDirectory && !finalExport) throw new Error('final EXPORT_DIR required');
  if (finalExport) {
    const target = realPath(finalExport);
    if (target === path.parse(target).root) throw new Error('dedicated export directory required');
    const dependencies = [sourcePath, mappingPath, outputPath, converterPath, process.argv[1], process.execPath,
      process.env.CONFIG_PATH, process.env.WORK_DIR, process.env.CACHE_DIR,
      process.env.RUNTIME_PROFILE_PATH, process.env.JS_YAML_PATH, ...String(process.env.NODE_PATH || '').split(path.delimiter)].filter(Boolean);
    for (const item of dependencies) {
      const value = realPath(item);
      if (target === value || target.startsWith(value + path.sep) || value.startsWith(target + path.sep)) throw new Error('export dependency overlap');
    }
  }
  const converter = require(path.resolve(converterPath));
  if (converter.CONSUMER_CONTRACT !== 'local-socks-explicit-v1') throw new Error('incompatible converter');
  const yaml = require(process.env.JS_YAML_PATH ? path.resolve(process.env.JS_YAML_PATH) : 'js-yaml');
  const map = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
  const profile = yaml.load(fs.readFileSync(process.env.RUNTIME_PROFILE_PATH, 'utf8'));
  const previous = process.env.CONFIG_PATH && fs.existsSync(process.env.CONFIG_PATH)
    ? yaml.load(fs.readFileSync(process.env.CONFIG_PATH, 'utf8')) : undefined;
  const result = converter.convertConfig(yaml.load(fs.readFileSync(sourcePath, 'utf8')), map, {
    namespace: process.env.APPROVED_NAMESPACE, serverInstanceId: process.env.APPROVED_SERVER_INSTANCE_ID,
    portPlanVersion: process.env.APPROVED_PORT_PLAN_VERSION, maxAgeSeconds: Number(process.env.MAP_MAX_AGE_SECONDS || 129600),
    runtimeProfile: profile, runtimeProfileHash: process.env.APPROVED_RUNTIME_PROFILE_HASH, previousConfig: previous,
  });
  fs.writeFileSync(outputPath, yaml.dump(result.config, { noRefs: true, lineWidth: -1 }), { mode: 0o600 });
  fs.writeFileSync(outputPath + '.manifest.json', JSON.stringify({
    consumer_contract: map.consumer_contract, mapping_version: map.mapping_version,
    runtime_config_hash: result.runtime_config_hash, manifest_hash: result.manifest_hash,
    entries: result.manifest,
  }), { mode: 0o600 });
  if (exportDirectory) {
    if (!advertiseHost || /[\s/{}]/u.test(advertiseHost)) throw new Error('advertise host required');
    const host = advertiseHost.includes(':') && !advertiseHost.startsWith('[') ? '[' + advertiseHost + ']' : advertiseHost;
    fs.mkdirSync(exportDirectory, { recursive: true, mode: 0o700 });
    const all = [], plain = [];
    for (const region of map.regions) {
      const entries = result.manifest.filter(entry => entry.region === region.id).sort((a,b) => a.port - b.port);
      const lines = entries.map(entry => 'socks5://' + host + ':' + entry.port + '{' + entry.name.replace(/[\r\n]+/g, ' ').trim() + '}');
      fs.writeFileSync(path.join(exportDirectory, region.id + '.txt'), lines.length ? lines.join('\n') + '\n' : '', { mode: 0o600 });
      all.push(...lines); plain.push(...entries.map(entry => 'socks5://' + host + ':' + entry.port));
    }
    fs.writeFileSync(path.join(exportDirectory, 'all.txt'), all.length ? all.join('\n') + '\n' : '', { mode: 0o600 });
    fs.writeFileSync(path.join(exportDirectory, 'all-plain.txt'), plain.length ? plain.join('\n') + '\n' : '', { mode: 0o600 });
    fs.writeFileSync(path.join(exportDirectory, 'README.txt'), 'Target mapping ' + map.mapping_version + '\nNot yet applied.\n', { mode: 0o600 });
  }
} catch {
  process.stderr.write('convert-ranking: invalid or unapproved mapping, inventory, runtime profile or export path\n');
  process.exitCode = 1;
}

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { adapt } from '../adapter-047156.mjs';
import { fixture, source } from './support.mjs';
const fixtureTest = (name, fn) => test(name, { skip: !source }, fn);

function starts(f) { try { return fs.readFileSync(path.join(f.root, 'restart.log'), 'utf8').trim().split('\n').length; } catch { return 0; } }

test('unknown source and command IDs fail closed', () => {
  assert.throws(() => adapt(Buffer.from('not approved')), /unsupported_version/);
  const f = fixture();
  try {
    assert.throws(() => f.tool.directory('../escape'), /configuration_invalid/);
  } finally { f.close(); }
});

fixtureTest('hash adapter preserves filtering body; disables upstream lock/counters/restarts', () => {
  const original = fs.readFileSync(source);
  const transformed = adapt(original);
  assert.ok(transformed.replaceAll('\n exit 1', '').includes(original.toString().split('config_cus_up()')[1].split('config_su_check()')[0]));
  assert.ok(!transformed.includes('\ninc_job_counter\n'));
  assert.ok(!transformed.includes('\nset_lock\n'));
  assert.ok(!transformed.includes('dec_job_counter_and_restart "$restart"'));
  const checked = spawnSync('bash', ['-n'], { input: transformed });
  assert.equal(checked.status, 0, checked.stderr?.toString());
});

fixtureTest('real candidate child, process restart, one restart and duplicate requests', async () => {
  const f = fixture();
  try {
    await f.baseline();
    const before = fs.readFileSync(f.c.raw_config);
    assert.equal((await f.tool.snapshot()).identity_verified, false);
    const id = crypto.randomUUID();
    assert.equal(f.tool.start(id).phase, 'queued');
    assert.equal(f.tool.start(id).operation_id, id);
    assert.throws(() => f.tool.start(crypto.randomUUID()), /busy/);
    await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'succeeded', JSON.stringify(f.tool.receipt(id)));
    assert.notDeepEqual(fs.readFileSync(f.c.raw_config), before);
    assert.equal(starts(f), 2); // baseline + one requested restart
    assert.equal((await f.tool.snapshot()).identity_verified, true);
    assert.deepEqual((await f.tool.snapshot()).nodes.map(x => x.name), ['A', 'B']);
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.root, 'choices.json'))).ChatGPT, 'DIRECT');
    await f.tool.work(id);
    assert.equal(starts(f), 2);
    assert.ok(!JSON.stringify(f.tool.receipt(id)).includes('synthetic-secret'));
  } finally { f.close(); }
});

fixtureTest('no-change download still performs exactly one requested restart', async () => {
  const f = fixture();
  try {
    await f.baseline();
    fs.writeFileSync(path.join(f.root, 'mode'), 'unchanged');
    const previous = fs.readFileSync(f.c.raw_config);
    const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'succeeded', JSON.stringify(f.tool.receipt(id)));
    assert.deepEqual(fs.readFileSync(f.c.raw_config), previous);
    assert.equal(starts(f), 2);
  } finally { f.close(); }
});

fixtureTest('failed download and invalid candidate leave original process/config intact', async () => {
  for (const mode of ['download-fail', 'invalid']) {
    const f = fixture();
    try {
      await f.baseline();
      fs.writeFileSync(path.join(f.root, 'mode'), mode);
      if (mode === 'invalid') fs.writeFileSync(path.join(f.root, 'incoming.json'), '{}');
      const before = fs.readFileSync(f.c.raw_config);
      const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
      assert.equal(f.tool.receipt(id).state, 'failed');
      assert.deepEqual(fs.readFileSync(f.c.raw_config), before);
      assert.equal(starts(f), 1);
    } finally { f.close(); }
  }
});

fixtureTest('a restart returning zero but retaining old process rolls back', async () => {
  const f = fixture();
  try {
    await f.baseline();
    fs.writeFileSync(path.join(f.root, 'mode'), 'ignore');
    const before = fs.readFileSync(f.c.raw_config);
    const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'rolled_back', JSON.stringify(f.tool.receipt(id)));
    assert.deepEqual(fs.readFileSync(f.c.raw_config), before);
    assert.equal(starts(f), 3);
  } finally { f.close(); }
});

fixtureTest('failed recovery is unknown and blocks another update', async () => {
  const f = fixture();
  try {
    await f.baseline();
    fs.writeFileSync(path.join(f.root, 'mode'), 'fail-all');
    const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'unknown');
    assert.throws(() => f.tool.start(crypto.randomUUID()), /busy/);
  } finally { f.close(); }
});

fixtureTest('lost lock or active upstream jobs prevents replacement', async () => {
  for (const flag of ['lost-lock', 'busy-jobs']) {
    const f = fixture();
    try {
      await f.baseline(); fs.writeFileSync(path.join(f.root, flag), '1');
      const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
      assert.equal(f.tool.receipt(id).state, 'failed');
      assert.equal(starts(f), 1);
    } finally { f.close(); }
  }
});

fixtureTest('SSH/request process exits but detached worker finishes once', async () => {
  const f = fixture();
  try {
    await f.baseline(); fs.writeFileSync(path.join(f.root, 'mode'), 'slow');
    const id = crypto.randomUUID();
    const launcher = path.join(f.root, 'launcher.mjs');
    fs.writeFileSync(launcher, `import { fixture } from ${JSON.stringify(new URL('./support.mjs', import.meta.url).href)};\nimport {spawn} from 'node:child_process';\nconst f=fixture(${JSON.stringify(f.root)});f.dependencies.launch=id=>{const p=spawn(process.execPath,[${JSON.stringify(fileURLToPath(new URL('./worker-fixture.mjs', import.meta.url)))},${JSON.stringify(f.root)},id],{detached:true,stdio:'ignore',env:process.env});p.unref()};f.tool.start(${JSON.stringify(id)});`);
    const launch = spawnSync(process.execPath, [launcher], { env: process.env, encoding: 'utf8', timeout: 5000 });
    assert.equal(launch.status, 0, launch.stderr);
    const deadline = Date.now() + 7000;
    while (f.tool.receipt(id).state === 'running' && Date.now() < deadline) await new Promise(r => setTimeout(r, 60));
    assert.equal(f.tool.receipt(id).state, 'succeeded', JSON.stringify(f.tool.receipt(id)));
    assert.equal(starts(f), 2);
  } finally { f.close(); }
});

fixtureTest('main core symlink is hashed as its actual large-file target', async () => {
  const f = fixture();
  try {
    fs.appendFileSync(f.c.core, Buffer.alloc(17 * 1024 * 1024));
    await f.baseline();
    const real = f.c.core + '.real';
    fs.renameSync(f.c.core, real);
    fs.symlinkSync(real, f.c.core);
    assert.ok(f.tool.process(f.c.core, f.c.runtime_config));
    const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'succeeded');
  } finally { f.close(); }
});

fixtureTest('saved manual selection is restored if the native restart resets it', async () => {
  const f = fixture();
  try {
    await f.baseline();
    fs.writeFileSync(path.join(f.root, 'mode'), 'reset-choices');
    const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'succeeded');
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.root, 'choices.json'))).ChatGPT, 'DIRECT');
  } finally { f.close(); }
});

fixtureTest('new process with stale runtime cannot attest a changed candidate', async () => {
  const f = fixture();
  try {
    await f.baseline();
    fs.writeFileSync(path.join(f.root, 'mode'), 'stale-runtime');
    const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'rolled_back');
    assert.equal(JSON.parse(fs.readFileSync(f.c.raw_config)).proxies[0].server, 'old.example');
  } finally { f.close(); }
});

test('verify rejects missing provenance and selection writes require readback', async () => {
  const f = fixture();
  try {
    await assert.rejects(f.tool.verify(null, 'a'.repeat(64), null), /runtime_attestation_required/);
    f.dependencies.controller = async method => method === 'PUT' ? {} : {
      Select: { type: 'Selector', all: ['US', 'DIRECT'], now: 'US' },
      Auto: { type: 'URLTest', all: ['A', 'B'], now: 'A', fixed: 'B' },
    };
    await assert.rejects(f.tool.restoreSelections({ Select: { type: 'Selector', now: 'DIRECT' } }), /selection_not_restored/);
    assert.deepEqual((await f.tool.restoreSelections({ Auto: { type: 'URLTest', fixed: 'B' } })).restored, ['Auto']);
    assert.equal(fs.existsSync(path.join(f.c.state_dir, 'loaded.json')), false);
  } finally { f.close(); }
});

fixtureTest('Ruby validator or keyword-filter failure cannot apply a candidate', async () => {
  for (const filterOnly of [false, true]) {
    const f = fixture();
    try {
      await f.baseline();
      const ruby = path.join(f.root, 'bin/ruby');
      fs.writeFileSync(ruby, filterOnly ? '#!/bin/sh\ncase "$*" in *"Filter Proxies Failed"*) exit 1;; esac\nexit 0\n' : '#!/bin/sh\nexit 1\n');
      if (filterOnly) {
        const lib = path.join(f.root, 'library.sh');
        let contents = fs.readFileSync(lib, 'utf8').replace("sub_convert) val=0;;", "sub_convert) val=0;; keyword) val=A;;");
        contents = contents.replace('config_list_foreach() { :; }', 'config_list_foreach() { if [ "$2" = keyword ]; then "$3" A keyword; fi; }');
        fs.writeFileSync(lib, contents);
      }
      const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
      assert.equal(f.tool.receipt(id).state, 'failed');
      assert.equal(starts(f), 1);
      assert.equal(JSON.parse(fs.readFileSync(f.c.raw_config)).proxies[0].server, 'old.example');
    } finally { f.close(); }
  }
});

fixtureTest('rollback preserves external raw edits and leaves the operation unknown', async () => {
  const f = fixture();
  try {
    await f.baseline();
    const restart = f.dependencies.restartAttested;
    f.dependencies.restartAttested = async attempt => {
      await restart(attempt);
      const external = JSON.parse(fs.readFileSync(f.c.raw_config));
      external.proxies[0].server = 'external-change.example';
      fs.writeFileSync(f.c.raw_config, JSON.stringify(external));
      throw new Error('restart_failed');
    };
    const id = crypto.randomUUID(); f.tool.start(id); await f.tool.work(id);
    assert.equal(f.tool.receipt(id).state, 'unknown');
    assert.equal(f.tool.receipt(id).error_code, 'rollback_conflict');
    assert.equal(JSON.parse(fs.readFileSync(f.c.raw_config)).proxies[0].server, 'external-change.example');
    assert.equal(starts(f), 2);
  } finally { f.close(); }
});

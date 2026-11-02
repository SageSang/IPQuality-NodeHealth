import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {work,recordAutomaticAttestation} from '../hot-reload.mjs';
import {Toolkit} from '../toolkit.mjs';

async function fixture(fn, {throws=false,changed=false,outputPolicy='catalog'}={}) {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sidora-hot-'));
 try {
  const raw=path.join(dir,'source.yaml'),runtime=path.join(dir,'runtime.yaml');
  fs.writeFileSync(raw,'synthetic-source');fs.writeFileSync(runtime,'synthetic-runtime');
  const core={pid:42,started:'100',boot_id:'test'},local={pid:43,started:'101',boot_id:'test'};
  const saves=[];let calls=0;
  const tool={c:{raw_config:raw,runtime_config:runtime,core:'synthetic-core',state_dir:dir,
   local_socks_core:'synthetic-local',local_socks_config:'synthetic.yaml',refresh_sha256:'a'.repeat(64)},
   deps:{hotLockHeld:true,env:{OPENCLASH_REFRESH_ENABLED:'1',OPENCLASH_OUTPUT_POLICY:outputPolicy,
    OPENCLASH_RUNTIME_CONFIG:runtime,OPENCLASH_SOURCE_CONFIG:raw,OPENCLASH_CORE:'synthetic-core',
    CACHE_DIR:'/etc/local-socks/cache/node-health'},
    refresh:async(env,cache)=>{calls++;assert.equal(env.OPENCLASH_REFRESH_INTERVAL_SECONDS,'0');
      assert.equal(env.OPENCLASH_FORCE_ATTESTATION,'1');
      assert.equal(cache,'/etc/local-socks/cache/node-health');if(throws)throw Error('private secret');return {applied:true,unchanged:true}}},
   approved:()=>{},receipt:()=>({state:'running',phase:'queued'}),busyJobs:()=>false,
   process:(file)=>file==='synthetic-core' ? (changed&&calls?{...core,pid:99}:core):local,
   snapshot:async()=>({groups_verified:true,process:core,configuration_sha256:'b'.repeat(64)}),
   save:(_,row)=>saves.push(row)};
  await fn(tool,saves,()=>calls,dir);
 } finally {fs.rmSync(dir,{recursive:true,force:true})}
}

test('manual refresh delegates once, bypasses only interval, certifies same process',async()=>fixture(async(tool,saves,calls,dir)=>{
 await work(tool,'00000000-0000-4000-8000-000000000001');
 assert.equal(calls(),1);assert.equal(saves.at(-1).state,'succeeded');
 assert.equal(saves.at(-1).result.restart_performed,false);
 assert.equal(saves.at(-1).result.local_socks_unchanged,true);
 assert.equal(JSON.parse(fs.readFileSync(path.join(dir,'loaded.json'))).schema_version,2);
}));

test('passthrough refresh retains full catalog and performs the same explicit identity proof',async()=>fixture(async(tool,saves,calls,dir)=>{
 await work(tool,'00000000-0000-4000-8000-000000000001');
 assert.equal(calls(),1);assert.equal(saves.at(-1).state,'succeeded');
 assert.equal(tool.deps.env.OPENCLASH_OUTPUT_POLICY,'passthrough');
 assert.equal(saves.at(-1).result.restart_performed,false);
 assert.equal(saves.at(-1).result.local_socks_unchanged,true);
 assert.equal(JSON.parse(fs.readFileSync(path.join(dir,'loaded.json'))).schema_version,2);
},{outputPolicy:'passthrough'}));

test('unrecognized output policy never launches refresh or certifies identity',async()=>fixture(async(tool,saves,calls,dir)=>{
 await work(tool,'00000000-0000-4000-8000-000000000001');
 assert.equal(calls(),0);assert.equal(saves.at(-1).state,'failed');
 assert.equal(saves.at(-1).error_code,'configuration_invalid');
 assert.equal(fs.existsSync(path.join(dir,'loaded.json')),false);
},{outputPolicy:'unexpected'}));

test('refresh error preserves unknown and strips upstream text',async()=>fixture(async(tool,saves)=>{
 await work(tool,'00000000-0000-4000-8000-000000000001');
 assert.equal(saves.at(-1).state,'unknown');assert.ok(!JSON.stringify(saves).includes('private secret'));
},{throws:true}));

test('unexpected core restart is never reported as successful hot reload',async()=>fixture(async(tool,saves)=>{
 await work(tool,'00000000-0000-4000-8000-000000000001');assert.equal(saves.at(-1).state,'unknown');
},{changed:true}));

test('terminal receipt is never dispatched twice',async()=>fixture(async(tool,saves,calls)=>{
 tool.receipt=()=>({state:'succeeded',phase:'completed'});
 await work(tool,'00000000-0000-4000-8000-000000000001');assert.equal(calls(),0);assert.equal(saves.length,0);
}));

test('an unbound process is not certified by an unchanged-file response',async()=>fixture(async(tool,saves,calls,dir)=>{
 tool.deps.refresh=async()=>({unchanged:true});
 await work(tool,'00000000-0000-4000-8000-000000000001');
 assert.equal(saves.at(-1).state,'unknown');
 assert.equal(fs.existsSync(path.join(dir,'loaded.json')),false);
}));

test('explicit hot action rejects a legacy configuration before any worker launch', async()=>{
 const tool=Object.create(Toolkit.prototype);tool.c={};let starts=0;
 tool.start=async()=>{starts++;return {state:'running'}};
 await assert.rejects(()=>tool.dispatch('start-hot','test-id'),/configuration_invalid/);
 assert.equal(starts,0);
 tool.c.update_mode='catalog_hot_reload';
 assert.equal((await tool.dispatch('start-hot','test-id')).state,'running');
 assert.equal(starts,1);
});

test('scheduled verified hot load refreshes identity without another reload',async()=>fixture(async(tool,saves,calls,dir)=>{
 tool.c.update_mode='catalog_hot_reload';
 const evidence={runtime:tool.c.runtime_config,source:tool.c.raw_config,core:tool.c.core,
  refresh_sha256:tool.c.refresh_sha256,transaction_id:'00000000-0000-4000-8000-000000000002',
  process:{pid:42,start:'100'},runtime_sha256:'b'.repeat(64)};
 const journal={outcome:'applied',pid:42,process_started:'100',runtime_sha256:'b'.repeat(64),refresh_sha256:tool.c.refresh_sha256};
 assert.equal((await recordAutomaticAttestation(evidence,{config:tool.c,tool,journal})).verified,true);
 const proof=JSON.parse(fs.readFileSync(path.join(dir,'loaded.json')));
 assert.equal(proof.attestation_source,'verified_scheduled_hot_reload');
 assert.equal(proof.operation_id,evidence.transaction_id);assert.equal(calls(),0);
}));

for(const conflict of ['failed-journal','changed-process','changed-file','unverified-groups']){
 test('scheduled attestation refuses '+conflict,async()=>fixture(async(tool,saves,calls,dir)=>{
  tool.c.update_mode='catalog_hot_reload';
  const evidence={runtime:tool.c.runtime_config,source:tool.c.raw_config,core:tool.c.core,
   refresh_sha256:tool.c.refresh_sha256,transaction_id:'00000000-0000-4000-8000-000000000002',
   process:{pid:42,start:conflict==='changed-process'?'99':'100'},
   runtime_sha256:(conflict==='changed-file'?'c':'b').repeat(64)};
  if(conflict==='unverified-groups')tool.snapshot=async()=>({groups_verified:false});
  await assert.rejects(()=>recordAutomaticAttestation(evidence,{config:tool.c,tool,
   journal:{outcome:conflict==='failed-journal'?'rolled-back':'applied',pid:42,
    process_started:'100',runtime_sha256:'b'.repeat(64),refresh_sha256:tool.c.refresh_sha256}}),/attestation_invalid/);
  assert.equal(fs.existsSync(path.join(dir,'loaded.json')),false);assert.equal(calls(),0);
 }));
}

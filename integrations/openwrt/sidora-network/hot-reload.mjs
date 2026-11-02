// Delegation only: downloading, output-policy checks, merge, PUT /configs,
// route verification and rollback belong to the existing refresh module.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const equal = (a,b) => JSON.stringify(a) === JSON.stringify(b);
function atomic(file, value) {
  const temp = `${file}.${crypto.randomUUID()}.new`;
  const fd = fs.openSync(temp,'wx',0o600);
  try {fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd)} finally {fs.closeSync(fd)}
  fs.renameSync(temp,file);
  const dir = fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}
}

// Called locally by the existing scheduled refresher only after its verified
// controller PUT and durable successful transaction receipt. No SSH action
// exposes this function. Automatic refreshes must retain the same identity proof
// as explicit App refreshes, without treating equal names as connection identity.
export async function recordAutomaticAttestation(evidence, deps={}) {
  const {Toolkit,loadConfiguration}=await import('./toolkit.mjs');
  const c=deps.config || loadConfiguration('/etc/sidora-network/config.json');
  const tool=deps.tool || new Toolkit(c);
  tool.approved();
  if(c.update_mode!=='catalog_hot_reload'||evidence.runtime!==c.runtime_config||
      evidence.source!==c.raw_config||evidence.core!==c.core||
      evidence.refresh_sha256!==c.refresh_sha256||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(evidence.transaction_id||'')) throw Error('attestation_invalid');
  const journal=deps.journal || JSON.parse(fs.readFileSync(path.join(c.local_socks_cache,'openclash',evidence.transaction_id+'.transaction.json.done'),'utf8'));
  const observed=await tool.snapshot();
  if(journal.outcome!=='applied'||journal.pid!==evidence.process?.pid||
      journal.process_started!==evidence.process?.start||journal.runtime_sha256!==evidence.runtime_sha256||
      journal.refresh_sha256!==evidence.refresh_sha256||
      !observed.groups_verified||observed.configuration_sha256!==evidence.runtime_sha256||
      observed.process?.pid!==evidence.process?.pid||observed.process?.started!==evidence.process?.start||
      !equal(observed.process,tool.process(c.core,c.runtime_config))) throw Error('attestation_invalid');
  atomic(path.join(c.state_dir,'loaded.json'),{schema_version:2,
    attestation_sha256:digest(JSON.stringify([evidence,journal,observed.process])),
    operation_id:evidence.transaction_id,process:observed.process,
    runtime_configuration_sha256:observed.configuration_sha256,
    attestation_source:'verified_scheduled_hot_reload'});
  return {verified:true};
}

export async function work(tool,id) {
  let launched = false;
  try {
    tool.approved();
    const c=tool.c, receipt=tool.receipt(id);
    if (['succeeded','failed','rolled_back'].includes(receipt.state)||receipt.phase!=='queued') return;
    const env=tool.deps.env || process.env;
    if (env.OPENCLASH_REFRESH_ENABLED!=='1'||!['catalog','passthrough'].includes(env.OPENCLASH_OUTPUT_POLICY)||
        env.OPENCLASH_RUNTIME_CONFIG!==c.runtime_config||env.OPENCLASH_SOURCE_CONFIG!==c.raw_config||
        env.OPENCLASH_CORE!==c.core||env.CACHE_DIR!=='/etc/local-socks/cache/node-health') throw Error('configuration_invalid');
    if (!tool.deps.hotLockHeld) {
      for (const [fd,file] of [[9,'/etc/local-socks/cache/node-health/apply.lock'],[8,'/tmp/lock/openclash_subs.lock']]) {
        const held=fs.fstatSync(fd), target=fs.statSync(file);
        if (held.ino!==target.ino||held.dev!==target.dev) throw Error('configuration_invalid');
      }
    }
    if(tool.busyJobs()) return tool.failBusy(id);
    const before=tool.process(c.core,c.runtime_config), local=tool.process(c.local_socks_core,c.local_socks_config);
    if(!before) throw Error('baseline_unverified');
    const baseline=await tool.snapshot();
    if(!baseline.groups_verified||!equal(before,baseline.process)) throw Error('baseline_unverified');
    const requiresAttestation=baseline.identity_verified!==true;
    const previous=digest(fs.readFileSync(c.raw_config));
    tool.save(id,{phase:'downloading'});
    const refresh=tool.deps.refresh || (await import('/etc/local-socks/openclash-refresh.mjs')).refreshOpenClash;
    launched=true;
    const result=await refresh({...env,OPENCLASH_REFRESH_INTERVAL_SECONDS:'0',
      OPENCLASH_FORCE_ATTESTATION:requiresAttestation?'1':'0'},env.CACHE_DIR);
    if(result?.skipped||(!result?.applied&&!result?.unchanged)) throw Error('refresh_unconfirmed');
    if(requiresAttestation&&result?.applied!==true) throw Error('refresh_unconfirmed');
    if(!equal(before,tool.process(c.core,c.runtime_config)) || !equal(local,tool.process(c.local_socks_core,c.local_socks_config))) throw Error('process_changed');
    const observed=await tool.snapshot();
    if(!observed.groups_verified||!equal(before,observed.process)) throw Error('refresh_unconfirmed');
    // This proof is emitted only after the shared module's verification and readback.
    atomic(path.join(c.state_dir,'loaded.json'),{schema_version:2,
      attestation_sha256:digest(JSON.stringify([id,c.refresh_sha256,observed.configuration_sha256,before,result])),
      operation_id:id,process:before,runtime_configuration_sha256:observed.configuration_sha256});
    tool.save(id,{state:'succeeded',phase:'completed',result:{verified:true,
      configuration_sha256:digest(fs.readFileSync(c.raw_config)),
      previous_configuration_sha256:previous,
      runtime_configuration_sha256:observed.configuration_sha256,
      process_id:before.pid,process_started:before.started,local_socks_unchanged:true,
      update_mode:'catalog_hot_reload',restart_performed:false,subscription_unchanged:result.unchanged===true}});
  }catch(error){
    // An interrupted transaction may be under the existing rollback watchdog.
    // Preserve uncertainty; never launch another update under the same receipt.
    tool.save(id,{state:launched?'unknown':'failed',phase:launched?'unknown':'failed',
      error_code:launched?'refresh_unconfirmed':(['unsupported_version','baseline_unverified','configuration_invalid'].includes(error.message)?error.message:'operation_failed')});
  }
}

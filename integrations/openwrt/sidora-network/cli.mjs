#!/usr/bin/env node
import { Toolkit, loadConfiguration } from './toolkit.mjs';

let value;
try {
  const config = loadConfiguration('/etc/sidora-network/config.json');
  const tool = new Toolkit(config);
  if (process.argv[2] === '--attest' && process.argv.length === 7) {
    tool.attest(process.argv[3], process.argv[4], process.argv[5], Number(process.argv[6]));
    process.exit(0);
  }
  if (process.argv[2] === '--worker' && process.argv.length === 4) {
    await tool.work(process.argv[3]);
    process.exit(0);
  }
  if (process.argv[2] === '--busy' && process.argv.length === 4) {
    tool.failBusy(process.argv[3]);
    process.exit(0);
  }
  if (process.argv.length !== 2) throw new Error('configuration_invalid');
  const command = process.env.SSH_ORIGINAL_COMMAND || '';
  const match = /^sidora-network-v1 (snapshot|fixed-ports|start|start-hot|operation)(?: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?$/.exec(command);
  if (!match || (['start', 'start-hot', 'operation'].includes(match[1]) !== Boolean(match[2]))) throw new Error('configuration_invalid');
  value = await tool.dispatch(match[1], match[2]);
} catch (error) {
  if (process.argv.length > 2) process.exitCode = 1;
  const known = ['busy', 'unknown_operation', 'unsupported_version', 'configuration_invalid'];
  value = { protocol: 'sidora-network-v1', error: known.includes(error.message) ? error.message : 'operation_failed' };
}
process.stdout.write(JSON.stringify(value) + '\n');

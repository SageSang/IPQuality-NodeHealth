import { fixture } from './support.mjs';
const [root, id, nonce, stage, pid] = process.argv.slice(2);
const f = fixture(root);
try { f.tool.attest(id, nonce, stage, Number(pid)); }
catch (error) { process.stderr.write(JSON.stringify({ stage, pid, parent: process.ppid }) + '\n'); throw error; }

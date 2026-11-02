import { fixture } from './support.mjs';
const f = fixture(process.argv[2]);
await f.tool.work(process.argv[3]);

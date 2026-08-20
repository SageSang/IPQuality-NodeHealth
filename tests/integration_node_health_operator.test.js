'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const operatorModule = require(path.join(
  __dirname,
  '..',
  'integrations',
  'sub-store',
  'health-ranking-operator.js',
));
const converter = require(path.join(
  __dirname,
  '..',
  'integrations',
  'local-socks',
  'convert-any-proxy-to-local-socks-stable.js',
));

function proxy(name, server, extra = {}) {
  return {
    name,
    type: 'vmess',
    server,
    port: 443,
    uuid: `secret-${server}`,
    tls: true,
    network: 'ws',
    'ws-opts': { path: '/ws', headers: { Host: 'edge.example.com' } },
    ...extra,
  };
}

function normalizeClashMetaProxy(value) {
  const item = JSON.parse(JSON.stringify(value));
  if (['vmess', 'vless'].includes(item.type) && Object.hasOwn(item, 'sni')) {
    item.servername = item.sni;
    delete item.sni;
  }
  if (item.network === 'ws') {
    item['ws-opts'] = item['ws-opts'] || {};
    if (!item['ws-opts'].path) item['ws-opts'].path = '/';
  }
  if (['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls'].includes(item.type)) {
    delete item.tls;
  }
  for (const key of Object.keys(item)) {
    if (key.startsWith('_') || item[key] == null) delete item[key];
  }
  return item;
}

function proxyUtilsFor(state, overrides = {}) {
  return {
    download: async () => JSON.stringify(state),
    produce: (proxies, target, type, options) => {
      assert.strictEqual(target, 'ClashMeta');
      assert.strictEqual(type, 'internal');
      assert.strictEqual(options['delete-underscore-fields'], true);
      return proxies.map(normalizeClashMetaProxy);
    },
    ...overrides,
  };
}

async function testIdentityVector() {
  const vector = {
    name: 'US display name',
    _runtime: 'ignored',
    type: 'vmess',
    server: 'example.com',
    port: 443,
    uuid: 'secret',
    tls: true,
    network: 'ws',
    'ws-opts': { path: '/ws', headers: { Host: 'edge.example.com' } },
  };
  const expected = '1811ab43423a2b26e7f6ee03483b1d19a566f3929e30e593b6defac6071a2a92';
  assert.strictEqual(operatorModule.nodeKey(vector), expected);
  assert.strictEqual(converter.nodeKey(vector), expected);
  assert.strictEqual(
    operatorModule.nodeKey({ ...vector, name: 'renamed', _runtime: 'changed' }),
    expected,
  );
  assert.notStrictEqual(operatorModule.nodeKey({ ...vector, uuid: 'new-secret' }), expected);
  const hopping = {
    name: 'HY2 hopping',
    type: 'hysteria2',
    server: 'hopping.example',
    port: 20001,
    ports: '20000-20100',
    password: 'secret',
  };
  const alternatePort = { ...hopping, port: 20099 };
  assert.strictEqual(operatorModule.nodeKey(hopping), operatorModule.nodeKey(alternatePort));
  assert.strictEqual(converter.nodeKey(hopping), converter.nodeKey(alternatePort));
}

async function testOperatorOrderingAndCompleteFallback() {
  const stable = proxy('US stable', 'stable.example');
  const stableUnavailable = proxy('US stable unavailable', 'stable-unavailable.example');
  const stableLater = proxy('US stable three', 'stable-three.example');
  const ranked = proxy('US ranked', 'ranked.example');
  const rejected = proxy('US rejected', 'rejected.example');
  const unknown = proxy('Unknown', 'unknown.example');
  const state = {
    schema_version: 1,
    version: 'test-v1',
    region_order: ['united-states'],
    regions: {
      'united-states': {
        stable_slots: {
          1: operatorModule.nodeKey(stable),
          2: operatorModule.nodeKey(stableUnavailable),
          3: operatorModule.nodeKey(stableLater),
        },
        ranked: [operatorModule.nodeKey(ranked)],
        rejected: {
          [operatorModule.nodeKey(stableUnavailable)]: 'quick_unavailable',
          [operatorModule.nodeKey(rejected)]: 'danger',
        },
      },
      other: { stable_slots: {}, ranked: [], rejected: {} },
    },
  };
  const input = [unknown, rejected, ranked, stableLater, stableUnavailable, stable];
  const context = {
    options: { rankingUrl: 'http://node-health.invalid/current.json' },
    ProxyUtils: proxyUtilsFor(state),
  };
  const output = await operatorModule.operator(input, 'ClashMeta', context);
  assert.deepStrictEqual(output.map((item) => item.name), [
    'US stable',
    'US stable unavailable',
    'US stable three',
    'US ranked',
    'US rejected',
    'Unknown',
  ]);

  const originalError = console.error;
  console.error = () => {};
  try {
    const fallback = await operatorModule.operator(input, 'ClashMeta', {
      options: context.options,
      ProxyUtils: proxyUtilsFor(state, {
        download: async () => { throw new Error('offline'); },
      }),
    });
    assert.deepStrictEqual(fallback, input);
  } finally {
    console.error = originalError;
  }
}

async function testOperatorRejectsNonArrayInput() {
  const originalError = console.error;
  console.error = () => {};
  try {
    await assert.rejects(
      () => operatorModule.operator({ proxies: [] }, 'ClashMeta', {}),
      /proxy input must be an array/,
    );
  } finally {
    console.error = originalError;
  }
}

async function testScriptArgumentsAndClashMetaNormalization() {
  const vmess = {
    name: 'VMess internal',
    type: 'vmess',
    server: 'vmess.example',
    port: 443,
    uuid: '11111111-1111-4111-8111-111111111111',
    tls: true,
    sni: 'vmess-sni.example',
    network: 'ws',
    'ws-opts': { headers: { Host: 'cdn.example' } },
    _runtime: 'ignored',
  };
  const vless = {
    name: 'VLESS internal',
    type: 'vless',
    server: 'vless.example',
    port: 443,
    uuid: '22222222-2222-4222-8222-222222222222',
    tls: true,
    sni: 'vless-sni.example',
    network: 'ws',
  };
  const trojan = {
    name: 'Trojan internal',
    type: 'trojan',
    server: 'trojan.example',
    port: 443,
    password: 'secret',
    tls: true,
    sni: 'trojan-sni.example',
  };
  const normalized = [vmess, vless, trojan].map(normalizeClashMetaProxy);
  const state = {
    schema_version: 1,
    version: 'normalization-v1',
    regions: {
      'united-states': {
        stable_slots: {
          1: operatorModule.nodeKey(normalized[1]),
          2: operatorModule.nodeKey(normalized[0]),
        },
        ranked: [operatorModule.nodeKey(normalized[2])],
        rejected: {},
      },
    },
  };
  const calls = [];
  const utilities = proxyUtilsFor(state, {
    produce: (proxies, target, type, options) => {
      calls.push({ target, type, options });
      return proxies.map(normalizeClashMetaProxy);
    },
  });
  const source = fs.readFileSync(path.join(
    __dirname,
    '..',
    'integrations',
    'sub-store',
    'health-ranking-operator.js',
  ), 'utf8');
  const dynamicOperator = new Function(
    '$arguments',
    '$options',
    'ProxyUtils',
    `${source}\nreturn operator;`,
  )(
    { rankingUrl: 'http://node-health.invalid/current.json' },
    { _req: { target: 'Surge' } },
    utilities,
  );

  const output = await dynamicOperator([trojan, vmess, vless], 'Surge', {});
  assert.deepStrictEqual(output.map((item) => item.name), [
    'VLESS internal',
    'VMess internal',
    'Trojan internal',
  ]);
  assert.ok(calls.length === 3);
  for (const call of calls) {
    assert.strictEqual(call.target, 'ClashMeta');
    assert.strictEqual(call.type, 'internal');
    assert.strictEqual(call.options['delete-underscore-fields'], true);
  }
  for (const item of normalized) {
    assert.strictEqual(operatorModule.nodeKey(item), converter.nodeKey(item));
  }
}

async function testOperatorPreservesInputForIncompleteRankingState() {
  const kept = proxy('Keep original', 'keep.example');
  const input = [kept];
  const invalidStates = [
    {
      label: 'empty regions',
      state: { schema_version: 1, version: 'empty-regions', regions: {} },
    },
    {
      label: 'empty decision shell',
      state: {
        schema_version: 1,
        version: 'empty-shell',
        regions: { other: { stable_slots: {}, ranked: [], rejected: {} } },
      },
    },
    {
      label: 'non-object region payload',
      state: { schema_version: 1, version: 'bad-region', regions: { other: [] } },
    },
    {
      label: 'missing stable slots',
      state: {
        schema_version: 1,
        version: 'missing-slots',
        regions: { other: { ranked: [operatorModule.nodeKey(kept)], rejected: {} } },
      },
    },
    {
      label: 'ranked is not an array',
      state: {
        schema_version: 1,
        version: 'bad-ranked',
        regions: { other: { stable_slots: {}, ranked: {}, rejected: {} } },
      },
    },
    {
      label: 'rejected is not an object',
      state: {
        schema_version: 1,
        version: 'bad-rejected',
        regions: { other: { stable_slots: {}, ranked: [], rejected: [] } },
      },
    },
    {
      label: 'node decision is not a sha256 key',
      state: {
        schema_version: 1,
        version: 'bad-key',
        regions: {
          other: { stable_slots: {}, ranked: ['not-a-node-key'], rejected: {} },
        },
      },
    },
    {
      label: 'legacy stable slot exceeds three-slot contract',
      state: {
        schema_version: 1,
        version: 'legacy-slot-four',
        regions: {
          'united-states': {
            stable_slots: { 4: operatorModule.nodeKey(kept) },
            ranked: [],
            rejected: {},
          },
        },
      },
    },
  ];

  const originalError = console.error;
  console.error = () => {};
  try {
    for (const item of invalidStates) {
      const output = await operatorModule.operator(input, 'ClashMeta', {
          options: { rankingUrl: 'http://node-health.invalid/current.json' },
          ProxyUtils: proxyUtilsFor(item.state),
        });
      assert.deepStrictEqual(output, input, `${item.label} must preserve the collection`);
    }
  } finally {
    console.error = originalError;
  }

  const rejectedKey = operatorModule.nodeKey(kept);
  const allRejected = await operatorModule.operator(input, 'ClashMeta', {
    options: { rankingUrl: 'http://node-health.invalid/current.json' },
    ProxyUtils: proxyUtilsFor({
        schema_version: 1,
        version: 'all-rejected',
        regions: {
          other: {
            stable_slots: {},
            ranked: [],
            rejected: { [rejectedKey]: 'danger' },
          },
        },
      }),
  });
  assert.deepStrictEqual(allRejected, input, 'an explicit all-rejected state keeps every node');
}

async function testIdentityDriftKeepsUnknownNodes() {
  const input = [proxy('Keep original', 'source.example')];
  const state = {
    schema_version: 1,
    version: 'identity-drift',
    regions: {
      other: {
        stable_slots: {},
        ranked: ['f'.repeat(64)],
        rejected: {},
      },
    },
  };
  const originalError = console.error;
  console.error = () => {};
  try {
    const output = await operatorModule.operator(input, 'ClashMeta', {
        options: { rankingUrl: 'http://node-health.invalid/current.json' },
        ProxyUtils: proxyUtilsFor(state),
      });
    assert.deepStrictEqual(output, input);
  } finally {
    console.error = originalError;
  }
}

async function testStablePortGaps() {
  const stableOne = proxy('US one', 'one.example');
  const stableUnavailable = proxy('US unavailable', 'unavailable.example');
  const dynamicOne = proxy('US candidate', 'candidate.example');
  const other = proxy('Brazil node', 'brazil.example');
  const unknown = proxy('US untested', 'untested.example');
  const ghostKey = 'e'.repeat(64);
  const keys = {
    stableOne: converter.nodeKey(stableOne),
    stableUnavailable: converter.nodeKey(stableUnavailable),
    dynamicOne: converter.nodeKey(dynamicOne),
    other: converter.nodeKey(other),
  };
  const state = {
    schema_version: 1,
    version: 'test-v2',
    regions: {
      'united-states': {
        stable_slots: {
          1: keys.stableOne,
          2: ghostKey,
          3: keys.stableUnavailable,
        },
        ranked: [keys.dynamicOne],
        rejected: { [keys.stableUnavailable]: 'quick_unavailable' },
      },
      other: { stable_slots: {}, ranked: [keys.other], rejected: {} },
    },
    nodes: {
      [keys.stableOne]: { region: 'united-states' },
      [keys.stableUnavailable]: { region: 'united-states' },
      [keys.dynamicOne]: { region: 'united-states' },
      [keys.other]: { region: 'other' },
    },
  };
  const ordering = operatorModule.buildOrdering(
    state,
    new Set([keys.stableOne, keys.stableUnavailable, keys.dynamicOne, keys.other]),
  ).order;
  assert.strictEqual(ordering.get(keys.stableOne), 0);
  assert.strictEqual(ordering.get(keys.dynamicOne), 1);
  assert.strictEqual(ordering.get(keys.stableUnavailable), 2);
  const output = converter.convertConfig(
    { proxies: [dynamicOne, unknown, other, stableUnavailable, stableOne] },
    state,
    62000,
  );
  const ports = Object.fromEntries(output.listeners.map((listener) => [listener.proxy, listener.port]));
  assert.strictEqual(ports['US one'], 62800);
  assert.strictEqual(ports['US unavailable'], 62802);
  assert.strictEqual(ports['US candidate'], 62801);
  assert.strictEqual(ports['Brazil node'], 64200);
  assert.strictEqual(ports['US untested'], 62803);
  const exported = output.listeners.map(
    (listener) => `socks5://192.0.2.4:${listener.port}{${listener.proxy}}`,
  );
  assert.ok(exported.includes('socks5://192.0.2.4:62800{US one}'));
  assert.ok(exported.includes('socks5://192.0.2.4:62801{US candidate}'));
  assert.ok(!exported.some((line) => line.includes('{unresolved}') || line.includes('{dynamic-')));
  assert.deepStrictEqual(output.dns, {
    enable: true,
    listen: '127.0.0.1:11553',
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'default-nameserver': ['114.114.114.114'],
    nameserver: ['https://doh.pub/dns-query'],
  });
  assert.strictEqual(operatorModule.STABLE_SLOT_COUNT, 3);
  assert.strictEqual(converter.STABLE_SLOT_COUNT, 3);
}

function testStableConverterRejectsIncompleteRankingState() {
  const input = { proxies: [proxy('Keep existing', 'keep-existing.example')] };
  const invalidStates = [
    { schema_version: 1, version: 'empty-regions', regions: {} },
    {
      schema_version: 1,
      version: 'empty-shell',
      regions: { other: { stable_slots: {}, ranked: [], rejected: {} } },
    },
    {
      schema_version: 1,
      version: 'bad-key',
      regions: {
        other: { stable_slots: {}, ranked: ['not-a-node-key'], rejected: {} },
      },
    },
    {
      schema_version: 1,
      version: 'legacy-slot-four',
      regions: {
        'united-states': {
          stable_slots: { 4: converter.nodeKey(input.proxies[0]) },
          ranked: [],
          rejected: {},
        },
      },
    },
  ];
  for (const state of invalidStates) {
    assert.throws(() => converter.convertConfig(input, state, 62000));
  }
}

function testPollerCacheIsolationContract() {
  const source = fs.readFileSync(path.join(
    __dirname,
    '..',
    'integrations',
    'openwrt',
    'check-ranking.sh',
  ), 'utf8');
  assert.ok(source.includes("--header 'Cache-Control: no-cache'"));
  assert.ok(source.includes("--header 'Pragma: no-cache'"));
  assert.ok(source.includes('_node_health_version=${encoded_version}'));
  const firstRanking = source.indexOf('download "$RANKING_URL" "$RANKING_FIRST"');
  const inventory = source.indexOf('download "$SOURCE_VERSION_URL" "$SOURCE_YAML"');
  const finalRanking = source.indexOf('download "$RANKING_URL" "$RANKING_FINAL"');
  assert.ok(firstRanking >= 0 && firstRanking < inventory && inventory < finalRanking);
  assert.ok(source.includes("LOCK_DIR='/tmp/node-health-check-ranking.lock.d'"));
  assert.ok(source.includes('APPLIED_CHECKSUM_FILE='));
  assert.ok(source.includes('exports_match_version()'));
  assert.ok(source.includes("jsonfilter -e '@.*.instances.*.running'"));
  assert.ok(source.includes('local-socks runtime self-heal failed'));
  assert.ok(source.includes('local-socks runtime recovered from local version'));
  assert.ok(source.includes('runtime_ready; then'));
  assert.ok(source.includes("trap 'exit 1' HUP INT TERM"));
}

function testRollbackRestoresRuntimePermissions() {
  const source = fs.readFileSync(path.join(
    __dirname,
    '..',
    'integrations',
    'openwrt',
    'apply-ranking.sh',
  ), 'utf8');
  const copy = source.indexOf('cp -p "$BACKUP" "$restore"');
  const mode = source.indexOf('chmod "$CONFIG_MODE" "$restore"');
  const owner = source.indexOf('chown "$CONFIG_OWNER" "$restore"');
  const replace = source.indexOf('mv -f "$restore" "$CONFIG_PATH"');
  assert.ok(copy >= 0 && copy < mode && mode < owner && owner < replace);
  assert.ok(source.includes('[ -n "$CONFIG_OWNER" ] && ! chown'));
  assert.ok(source.includes('rm -f -- "$restore"'));
  assert.ok(source.includes("START_PORT must be exactly 62000"));
  assert.ok(source.includes("trap 'exit 1' HUP INT TERM"));
  assert.ok(source.includes("jsonfilter -e '@.*.instances.*.running'"));
  assert.ok(source.includes('listeners_ready()'));
  assert.ok(source.includes("net.createConnection({ host: '127.0.0.1', port })"));
  assert.ok(source.includes("fail_after_rollback 'one or more configured listeners are not reachable'"));
  const readinessCall = source.lastIndexOf('if ! service_ready; then');
  const listenerCall = source.lastIndexOf('if ! listeners_ready; then');
  const exportCall = source.lastIndexOf('if ! publish_exports; then');
  assert.ok(readinessCall < listenerCall && listenerCall < exportCall);

  const runner = fs.readFileSync(path.join(
    __dirname,
    '..',
    'integrations',
    'openwrt',
    'convert-ranking.mjs',
  ), 'utf8');
  assert.ok(runner.includes('inventory has zero matches'));
  assert.ok(runner.includes("path.join(exportDirectory, 'all.txt')"));
  assert.ok(runner.includes("path.join(exportDirectory, 'all-plain.txt')"));
  assert.ok(runner.includes("dns.listen !== '127.0.0.1:11553'"));
  assert.ok(runner.includes("dns['enhanced-mode'] !== 'fake-ip'"));
  assert.ok(runner.includes('converter output must preserve the independent fake-IP DNS configuration'));

  const service = fs.readFileSync(path.join(
    __dirname,
    '..',
    'integrations',
    'openwrt',
    'service-lib.sh',
  ), 'utf8');
  assert.ok(service.includes('prepare_runtime_binary()'));
  assert.ok(service.includes('cmp -s "$MIHOMO_SOURCE" "$MIHOMO_BIN"'));
  assert.ok(service.includes('procd_set_param limits nofile="$LOCAL_SOCKS_NOFILE"'));
  assert.ok(service.includes('bin/mihomo-local-socks'));
}

(async () => {
  await testIdentityVector();
  await testOperatorOrderingAndCompleteFallback();
  await testOperatorRejectsNonArrayInput();
  await testScriptArgumentsAndClashMetaNormalization();
  await testOperatorPreservesInputForIncompleteRankingState();
  await testIdentityDriftKeepsUnknownNodes();
  await testStablePortGaps();
  testStableConverterRejectsIncompleteRankingState();
  testPollerCacheIsolationContract();
  testRollbackRestoresRuntimePermissions();
  process.stdout.write('integration_node_health_operator: ok\n');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

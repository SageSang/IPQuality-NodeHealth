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

// One shared vector set defines whitespace for Python and both standalone JS
// consumers. FEFF is content; the C0 separators and NEL are whitespace.
const identityWhitespace = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'identity-whitespace.json'), 'utf8'));
for (const [codes, isSpace] of [[identityWhitespace.whitespace_codepoints, true], [identityWhitespace.non_whitespace_codepoints, false]]) {
  for (const code of codes) {
    const character = String.fromCodePoint(parseInt(code, 16));
    const input = { name: 'Hong Kong Fallback', _nh_source_id: character, _source_id: 'BACKUP',
      _nh_original_name: character, _original_name: 'Hong Kong Original' };
    for (const consumer of [operatorModule, converter]) {
      assert.strictEqual(consumer.sourceId(input), isSpace ? 'backup' : character, `source U+${code}`);
      assert.strictEqual(consumer.originalName(input), isSpace ? 'Hong Kong Original' : character, `name U+${code}`);
      assert.strictEqual(consumer.normalizeIdentityText(`${character}Ａ${character}Ｂ${character}`),
        isSpace ? 'a b' : `${character}a${character}b${character}`, `normalize U+${code}`);
    }
  }
}

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

function addIdentityIndex(state) {
  if (!state || state.schema_version !== 2 || state.identity_index) return state;
  const identityIndex = {};
  for (const [regionKey, region] of Object.entries(state.regions || {})) {
    if (!region || typeof region !== 'object' || Array.isArray(region)) continue;
    const keys = [
      ...Object.values(region.stable_slots || {}),
      ...(Array.isArray(region.ranked) ? region.ranked : []),
      ...Object.keys(
        region.rejected && typeof region.rejected === 'object' && !Array.isArray(region.rejected)
          ? region.rejected
          : {},
      ),
    ].map((entry) =>
      typeof entry === 'string' ? entry : String((entry && entry.node_key) || ''),
    );
    for (const key of keys) {
      if (!/^[0-9a-f]{64}$/.test(key)) continue;
      identityIndex[key] = {
        source_id: '',
        original_name: key,
        normalized_name: key,
        logical_id: '',
        region: regionKey,
      };
    }
  }
  state.identity_index = identityIndex;
  return state;
}

function proxyUtilsFor(state, overrides = {}) {
  addIdentityIndex(state);
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
    schema_version: 2,
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
    schema_version: 2,
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
      state: { schema_version: 2, version: 'empty-regions', regions: {} },
    },
    {
      label: 'empty decision shell',
      state: {
        schema_version: 2,
        version: 'empty-shell',
        regions: { other: { stable_slots: {}, ranked: [], rejected: {} } },
      },
    },
    {
      label: 'non-object region payload',
      state: { schema_version: 2, version: 'bad-region', regions: { other: [] } },
    },
    {
      label: 'missing stable slots',
      state: {
        schema_version: 2,
        version: 'missing-slots',
        regions: { other: { ranked: [operatorModule.nodeKey(kept)], rejected: {} } },
      },
    },
    {
      label: 'ranked is not an array',
      state: {
        schema_version: 2,
        version: 'bad-ranked',
        regions: { other: { stable_slots: {}, ranked: {}, rejected: {} } },
      },
    },
    {
      label: 'rejected is not an object',
      state: {
        schema_version: 2,
        version: 'bad-rejected',
        regions: { other: { stable_slots: {}, ranked: [], rejected: [] } },
      },
    },
    {
      label: 'node decision is not a sha256 key',
      state: {
        schema_version: 2,
        version: 'bad-key',
        regions: {
          other: { stable_slots: {}, ranked: ['not-a-node-key'], rejected: {} },
        },
      },
    },
    {
      label: 'legacy stable slot exceeds three-slot contract',
      state: {
        schema_version: 2,
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
    {
      label: 'decision key missing from identity index',
      state: {
        schema_version: 2,
        version: 'missing-identity-entry',
        regions: {
          other: {
            stable_slots: {},
            ranked: [operatorModule.nodeKey(kept)],
            rejected: {},
          },
        },
        identity_index: {},
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
        schema_version: 2,
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
    schema_version: 2,
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

async function testLogicalIdentityKeepsRankingAcrossConnectionRotation() {
  const oldStable = proxy('Hong Kong 01', 'old-hk.example', {
    _nh_source_id: 'E-IX',
    _nh_original_name: 'Hong Kong 01',
  });
  const newStable = proxy('Hong Kong 01', 'new-hk.example', {
    _nh_source_id: 'E-IX',
    _nh_original_name: 'Hong Kong 01',
  });
  const ranked = proxy('Hong Kong 02', 'ranked-hk.example', {
    _nh_source_id: 'E-IX',
    _nh_original_name: 'Hong Kong 02',
  });
  const unknown = proxy('Unknown', 'unknown-rotation.example');
  const oldKey = operatorModule.nodeKey(normalizeClashMetaProxy(oldStable));
  const rankedKey = operatorModule.nodeKey(normalizeClashMetaProxy(ranked));
  const oldIdentity = operatorModule.selectedIdentity(oldStable);
  const rankedIdentity = operatorModule.selectedIdentity(ranked);
  const state = {
    schema_version: 2,
    version: 'identity-rotation-v2',
    region_order: ['hong-kong'],
    regions: {
      'hong-kong': {
        stable_slots: { 1: oldKey },
        ranked: [rankedKey],
        rejected: {},
      },
    },
    identity_index: {
      [oldKey]: oldIdentity,
      [rankedKey]: rankedIdentity,
    },
  };

  const output = await operatorModule.operator(
    [unknown, ranked, newStable],
    'ClashMeta',
    {
      options: { rankingUrl: 'http://node-health.invalid/current.json' },
      ProxyUtils: proxyUtilsFor(state),
    },
  );

  assert.deepStrictEqual(output.map((item) => item.name), [
    'Hong Kong 01',
    'Hong Kong 02',
    'Unknown',
  ]);
  assert.strictEqual(output.length, 3);
}

function testLogicalIdentityNeverCrossesKnownSources() {
  const oldProxy = proxy('Hong Kong 01', 'old-source.example', {
    _nh_source_id: 'airport-a',
    _nh_original_name: 'Hong Kong 01',
  });
  const newProxy = proxy('Hong Kong 01', 'new-source.example', {
    _nh_source_id: 'airport-b',
    _nh_original_name: 'Hong Kong 01',
  });
  const oldKey = operatorModule.nodeKey(normalizeClashMetaProxy(oldProxy));
  const state = {
    schema_version: 2,
    version: 'source-isolation-v2',
    regions: {
      'hong-kong': {
        stable_slots: { 1: oldKey },
        ranked: [],
        rejected: {},
      },
    },
    identity_index: { [oldKey]: operatorModule.selectedIdentity(oldProxy) },
  };
  const selected = [{
    key: operatorModule.nodeKey(normalizeClashMetaProxy(newProxy)),
    identity: operatorModule.selectedIdentity(newProxy),
  }];

  assert.deepStrictEqual([...operatorModule.resolveIdentityKeys(state, selected)], []);
}

function testNormalizedUniqueNameFallbackAndAmbiguityGuard() {
  const oldProxy = proxy('Hong   Kong 01', 'old-normalized.example');
  const newProxy = proxy('hong kong 01', 'new-normalized.example');
  const duplicate = proxy('HONG KONG 01', 'duplicate-normalized.example');
  const oldKey = operatorModule.nodeKey(normalizeClashMetaProxy(oldProxy));
  const state = {
    schema_version: 2,
    version: 'normalized-name-v2',
    regions: {
      'hong-kong': {
        stable_slots: { 1: oldKey },
        ranked: [],
        rejected: {},
      },
    },
    identity_index: { [oldKey]: operatorModule.selectedIdentity(oldProxy) },
  };
  const one = [{
    key: operatorModule.nodeKey(normalizeClashMetaProxy(newProxy)),
    identity: operatorModule.selectedIdentity(newProxy),
  }];
  assert.strictEqual(operatorModule.resolveIdentityKeys(state, one).get(0), oldKey);

  const ambiguous = [newProxy, duplicate].map((item) => ({
    key: operatorModule.nodeKey(normalizeClashMetaProxy(item)),
    identity: operatorModule.selectedIdentity(item),
  }));
  assert.deepStrictEqual([...operatorModule.resolveIdentityKeys(state, ambiguous)], []);
}

function testExactConnectionIdentityPrecedesLogicalSourceMismatch() {
  const oldProxy = proxy('Hong Kong old', 'exact.example', {
    _nh_source_id: 'airport-a',
  });
  const renamed = proxy('Hong Kong renamed', 'exact.example', {
    _nh_source_id: 'airport-b',
  });
  const oldKey = operatorModule.nodeKey(normalizeClashMetaProxy(oldProxy));
  const state = {
    schema_version: 2,
    version: 'exact-precedence-v2',
    regions: {
      'hong-kong': { stable_slots: { 1: oldKey }, ranked: [], rejected: {} },
    },
    identity_index: { [oldKey]: operatorModule.selectedIdentity(oldProxy) },
  };
  const selected = [{
    key: operatorModule.nodeKey(normalizeClashMetaProxy(renamed)),
    identity: operatorModule.selectedIdentity(renamed),
  }];

  assert.strictEqual(selected[0].key, oldKey);
  assert.strictEqual(operatorModule.resolveIdentityKeys(state, selected).get(0), oldKey);
}

async function testOperatorPreservesAll250InputsAndUnknownTailOrder() {
  const stable = proxy('US stable bulk', 'bulk-stable.example');
  const stableKey = operatorModule.nodeKey(normalizeClashMetaProxy(stable));
  const unknown = Array.from({ length: 249 }, (_, index) =>
    proxy(`Unknown bulk ${String(index).padStart(3, '0')}`, `bulk-${index}.example`),
  );
  const input = [...unknown, stable];
  const state = {
    schema_version: 2,
    version: 'bulk-250-v2',
    regions: {
      'united-states': {
        stable_slots: { 1: stableKey },
        ranked: [],
        rejected: {},
      },
    },
    identity_index: { [stableKey]: operatorModule.selectedIdentity(stable) },
  };

  const output = await operatorModule.operator(input, 'ClashMeta', {
    options: { rankingUrl: 'http://node-health.invalid/current.json' },
    ProxyUtils: proxyUtilsFor(state),
  });

  assert.strictEqual(output.length, 250);
  assert.strictEqual(output[0], stable);
  assert.deepStrictEqual(output.slice(1), unknown);
  assert.strictEqual(new Set(output).size, 250);
}

function testFixedConsumerRejectsLegacyRankingAndMissingApprovals() {
  const input = { proxies: [proxy('Hong Kong A', 'a.example')] };
  assert.throws(() => converter.convertConfig(input, {schema_version: 2, version: 'legacy', regions: {}}), /unsupported/);
  assert.throws(() => converter.convertConfig(input, {
    schema_version: 1, consumer_contract: 'local-socks-explicit-v1',
    purpose: 'production', application_status: 'target-only',
  }), /unapproved/);
}

function testOperatorDoesNotInventStableSlots() {
  const keys = ['a', 'b', 'c'].map(letter => letter.repeat(64));
  const state = addIdentityIndex({
    schema_version: 2, version: 'sparse', regions: {
      'hong-kong': {stable_slots: {2: keys[0], 3: keys[1]}, ranked: [keys[2]], rejected: {}},
    },
  });
  const ordering = operatorModule.buildOrdering(state, new Set(keys)).order;
  assert.strictEqual(ordering.get(keys[0]), 0);
  assert.strictEqual(ordering.get(keys[1]), 1);
  assert.strictEqual(ordering.get(keys[2]), 2);
}

async function testSubscriptionPinOverlay() {
  const proxies = ['A', 'B', 'C', 'D', 'E', 'F'].map(name => proxy(`US ${name}`, `${name}.example`));
  const keys = proxies.map(item => operatorModule.nodeKey(normalizeClashMetaProxy(item)));
  const state = {
    schema_version: 2, version: 'pin-overlay', region_order: ['united-states'],
    regions: {'united-states': {stable_slots: {1: keys[0], 2: keys[1], 3: keys[2]},
      ranked: keys.slice(3), rejected: {[keys[4]]: 'unavailable'}}},
    identity_index: Object.fromEntries(proxies.map((item, i) => [keys[i], operatorModule.selectedIdentity(item)])),
  };
  const input = [...proxies].reverse();
  const run = (list = input) => operatorModule.operator(list, 'ClashMeta', {
    options: {rankingUrl: 'http://node-health.invalid/current.json'}, ProxyUtils: proxyUtilsFor(state),
  });
  const baseline = await run();
  assert.deepStrictEqual(baseline, proxies);
  for (const [pins, expected] of [
    [[4], [4, 0, 1, 2, 3, 5]], [[1], [1, 0, 2, 3, 4, 5]],
    [[4, 1], [4, 1, 0, 2, 3, 5]], [[4, 1, 5], [4, 1, 5, 0, 2, 3]], [[], [0, 1, 2, 3, 4, 5]],
  ]) {
    state.subscription_preferences = {schema_version: 1, status: 'ready', revision: 1,
      pinned_nodes: pins.map(i => keys[i])};
    const before = JSON.stringify(state);
    const output = await run();
    assert.deepStrictEqual(output, expected.map(i => proxies[i]));
    assert.strictEqual(JSON.stringify(state), before);
    assert.deepStrictEqual(output.filter(item => !pins.includes(proxies.indexOf(item))),
      baseline.filter(item => !pins.includes(proxies.indexOf(item))));
  }
  // No duplicate or invented entry when the pinned node isn't in this client's input.
  state.subscription_preferences.pinned_nodes = [keys[4], keys[1]];
  assert.deepStrictEqual(await run(input.filter(item => item !== proxies[4])),
    [proxies[1], proxies[0], proxies[2], proxies[3], proxies[5]]);
  // A malformed optional preference keeps the automatic ranking, not reversed input.
  for (const preferences of [{schema_version: 99}, {schema_version: 1, status: 'unavailable'},
    {schema_version: 1, status: 'ready', revision: 1, pinned_nodes: [keys[0], keys[0]]}]) {
    state.subscription_preferences = preferences;
    assert.deepStrictEqual(await run(), baseline);
  }
  delete state.subscription_preferences;
  assert.deepStrictEqual(await run(), baseline);

  // Aliases and repeated occurrences are preserved; the stable representative wins.
  const stableAlias = {...proxies[1], name: 'US B alias'};
  const dynamicAlias = {...proxies[4], name: 'US E alias'};
  const duplicate = {...proxies[4]};
  const all = [dynamicAlias, duplicate, stableAlias, ...input];
  const aliasesBaseline = await run(all);
  for (const pinned of [[keys[1]], [keys[4]], [keys[4], keys[1]]]) {
    state.subscription_preferences = {schema_version: 1, status: 'ready', revision: 2, pinned_nodes: pinned};
    const result = await run(all);
    const moved = result.slice(0, pinned.length);
    assert.strictEqual(result.length, all.length);
    for (const item of all) assert.strictEqual(result.filter(entry => entry === item).length, 1);
    assert.deepStrictEqual(result.slice(pinned.length), aliasesBaseline.filter(item => !moved.includes(item)));
    if (pinned.includes(keys[1])) assert.strictEqual(result[pinned.indexOf(keys[1])], proxies[1]);
  }
}

async function testPinsAcrossRegionsRotationAndFrozenOther() {
  const hk = proxy('Hong Kong A', 'hk.example');
  const old = proxy('Other B', 'old.example');
  const rotated = {...old, server: 'new.example'};
  const keys = [hk, old].map(item => operatorModule.nodeKey(normalizeClashMetaProxy(item)));
  const state = {schema_version: 2, version: 'global-pin', region_order: ['hong-kong', 'other'],
    regions: {'hong-kong': {stable_slots: {1: keys[0]}, ranked: [], rejected: {}},
      other: {stable_slots: {}, ranked: [keys[1]], rejected: {}}},
    identity_index: {[keys[0]]: operatorModule.selectedIdentity(hk), [keys[1]]: operatorModule.selectedIdentity(old)},
    subscription_preferences: {schema_version: 1, status: 'ready', revision: 3, pinned_nodes: [keys[1]]}};
  const before = JSON.stringify(state);
  const result = await operatorModule.operator([hk, rotated], 'ClashMeta', {
    options: {rankingUrl: 'http://node-health.invalid/current.json'}, ProxyUtils: proxyUtilsFor(state),
  });
  assert.deepStrictEqual(result, [rotated, hk]);
  assert.strictEqual(JSON.stringify(state), before);
}

(async () => {
  await testIdentityVector();
  await testOperatorOrderingAndCompleteFallback();
  await testOperatorRejectsNonArrayInput();
  await testScriptArgumentsAndClashMetaNormalization();
  await testOperatorPreservesInputForIncompleteRankingState();
  await testIdentityDriftKeepsUnknownNodes();
  await testLogicalIdentityKeepsRankingAcrossConnectionRotation();
  testLogicalIdentityNeverCrossesKnownSources();
  testNormalizedUniqueNameFallbackAndAmbiguityGuard();
  testExactConnectionIdentityPrecedesLogicalSourceMismatch();
  await testOperatorPreservesAll250InputsAndUnknownTailOrder();
  testFixedConsumerRejectsLegacyRankingAndMissingApprovals();
  testOperatorDoesNotInventStableSlots();
  await testSubscriptionPinOverlay();
  await testPinsAcrossRegionsRotationAndFrozenOther();
  process.stdout.write('integration_node_health_operator: ok\n');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

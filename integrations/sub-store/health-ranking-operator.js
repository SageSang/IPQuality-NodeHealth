/**
 * Sub-Store Script Operator for node-health ordering.
 *
 * Configure with $arguments.rankingUrl (or $arguments.url). Health data only
 * changes ordering: every proxy supplied by the complete collection is
 * returned exactly once, including rejected, unavailable and not-yet-ranked
 * nodes. Invalid or unavailable health data falls back to the input order.
 */

const NODE_HEALTH_SCHEMA_VERSION = 1;
const STABLE_SLOT_COUNT = 3;
const NODE_KEY_PATTERN = /^[0-9a-f]{64}$/;
const REGION_ORDER = [
  'hong-kong',
  'taiwan',
  'japan',
  'singapore',
  'united-states',
  'south-korea',
  'united-kingdom',
  'germany',
  'france',
  'canada',
  'australia',
  'other',
];

function compareCodePoints(left, right) {
  const a = Array.from(left);
  const b = Array.from(right);
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = a[index].codePointAt(0) - b[index].codePointAt(0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function canonicalJson(value, topLevel = false) {
  if (value === null) return 'null';

  if (Array.isArray(value)) {
    return `[${value
      .map((item) =>
        item === undefined || typeof item === 'function' || typeof item === 'symbol'
          ? 'null'
          : canonicalJson(item, false),
      )
      .join(',')}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((key) => {
        if (
          topLevel &&
          (key === 'name' ||
            key.startsWith('_') ||
            (key === 'port' && value.ports))
        ) return false;
        const item = value[key];
        return item !== undefined && typeof item !== 'function' && typeof item !== 'symbol';
      })
      .sort(compareCodePoints);

    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], false)}`)
      .join(',')}}`;
  }

  const serialized = JSON.stringify(value);
  return serialized === undefined ? 'null' : serialized;
}

function utf8Bytes(value) {
  if (typeof TextEncoder !== 'undefined') {
    return Array.from(new TextEncoder().encode(value));
  }

  const bytes = [];
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point <= 0x7f) {
      bytes.push(point);
    } else if (point <= 0x7ff) {
      bytes.push(0xc0 | (point >>> 6), 0x80 | (point & 0x3f));
    } else if (point <= 0xffff) {
      bytes.push(
        0xe0 | (point >>> 12),
        0x80 | ((point >>> 6) & 0x3f),
        0x80 | (point & 0x3f),
      );
    } else {
      bytes.push(
        0xf0 | (point >>> 18),
        0x80 | ((point >>> 12) & 0x3f),
        0x80 | ((point >>> 6) & 0x3f),
        0x80 | (point & 0x3f),
      );
    }
  }
  return bytes;
}

function rotateRight(value, bits) {
  return (value >>> bits) | (value << (32 - bits));
}

function sha256Hex(value) {
  const constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const input = utf8Bytes(value);
  const originalLength = input.length;
  const paddedLength = Math.ceil((originalLength + 9) / 64) * 64;
  const bytes = new Array(paddedLength).fill(0);
  for (let index = 0; index < originalLength; index += 1) bytes[index] = input[index];
  bytes[originalLength] = 0x80;

  const bitLengthHigh = Math.floor(originalLength / 0x20000000);
  const bitLengthLow = (originalLength << 3) >>> 0;
  for (let index = 0; index < 4; index += 1) {
    bytes[paddedLength - 8 + index] = (bitLengthHigh >>> (24 - index * 8)) & 0xff;
    bytes[paddedLength - 4 + index] = (bitLengthLow >>> (24 - index * 8)) & 0xff;
  }

  const words = new Array(64);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      const cursor = offset + index * 4;
      words[index] =
        ((bytes[cursor] << 24) |
          (bytes[cursor + 1] << 16) |
          (bytes[cursor + 2] << 8) |
          bytes[cursor + 3]) >>>
        0;
    }
    for (let index = 16; index < 64; index += 1) {
      const s0 =
        rotateRight(words[index - 15], 7) ^
        rotateRight(words[index - 15], 18) ^
        (words[index - 15] >>> 3);
      const s1 =
        rotateRight(words[index - 2], 17) ^
        rotateRight(words[index - 2], 19) ^
        (words[index - 2] >>> 10);
      words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index += 1) {
      const sigma1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (h + sigma1 + choice + constants[index] + words[index]) >>> 0;
      const sigma0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (sigma0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }

  return hash.map((word) => word.toString(16).padStart(8, '0')).join('');
}

function nodeKey(proxy) {
  if (!proxy || typeof proxy !== 'object' || Array.isArray(proxy)) {
    throw new TypeError('proxy must be an object');
  }
  return sha256Hex(canonicalJson(proxy, true));
}

function operatorOptions(context) {
  const candidates = [];
  if (context && typeof context === 'object') {
    candidates.push(context.options, context.params, context.arguments);
  }
  if (typeof $options !== 'undefined') candidates.push($options);
  // Script Operator passes UI/link arguments through this lexical global.
  // Keep it last so it has the highest precedence over request metadata.
  if (typeof $arguments !== 'undefined') candidates.push($arguments);

  const merged = {};
  for (const candidate of candidates) {
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      Object.assign(merged, candidate);
      continue;
    }
    if (typeof candidate === 'string') {
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          Object.assign(merged, parsed);
        }
      } catch (_) {
        // Ignore an unrelated context string.
      }
    }
  }
  return merged;
}

function noCacheUrl(url) {
  if (/(?:^|[&#])noCache(?:[=&]|$)/.test(url)) return url;
  return `${url}${url.includes('#') ? '&' : '#'}noCache`;
}

async function responseText(response) {
  if (typeof response === 'string') return response;
  if (response && typeof response.text === 'function') return response.text();
  for (const key of ['body', 'content', 'data']) {
    if (response && typeof response[key] === 'string') return response[key];
  }
  throw new Error('ranking response has no text body');
}

function proxyUtilities(context) {
  return (
    (context && context.ProxyUtils) ||
    (typeof ProxyUtils !== 'undefined' ? ProxyUtils : undefined)
  );
}

async function downloadRanking(url, context) {
  const utilities = proxyUtilities(context);
  if (utilities && typeof utilities.download === 'function') {
    return responseText(await utilities.download(noCacheUrl(url)));
  }
  if (typeof fetch === 'function') {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error(`ranking HTTP status ${response.status}`);
    return response.text();
  }
  throw new Error('no downloader is available');
}

function clashMetaNodeKey(proxy, context) {
  const utilities = proxyUtilities(context);
  if (!utilities || typeof utilities.produce !== 'function') {
    throw new Error('ProxyUtils.produce is unavailable');
  }
  const cloned = JSON.parse(JSON.stringify(proxy));
  const produced = utilities.produce(
    [cloned],
    'ClashMeta',
    'internal',
    { 'delete-underscore-fields': true },
  );
  if (!Array.isArray(produced)) {
    throw new Error('ClashMeta producer did not return an internal proxy array');
  }
  if (produced.length === 0) return '';
  if (produced.length !== 1 || !produced[0] || typeof produced[0] !== 'object') {
    throw new Error('ClashMeta producer returned an invalid normalized proxy');
  }
  return nodeKey(produced[0]);
}

function keyFromEntry(value) {
  if (typeof value === 'string') return value;
  if (!value || typeof value !== 'object') return '';
  return String(value.node_key || value.nodeKey || value.key || '');
}

function rejectedKeys(region) {
  const rejected = region && region.rejected;
  if (rejected && typeof rejected === 'object') return Object.keys(rejected);
  return [];
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validateRankingState(state) {
  if (
    !state ||
    state.schema_version !== NODE_HEALTH_SCHEMA_VERSION ||
    typeof state.version !== 'string' ||
    !state.version ||
    !isRecord(state.regions)
  ) {
    throw new Error('unsupported ranking schema');
  }

  const regions = Object.entries(state.regions);
  if (regions.length === 0) throw new Error('ranking regions are empty');

  let decisionKeys = 0;
  for (const [regionKey, region] of regions) {
    if (!regionKey || !isRecord(region)) {
      throw new Error(`invalid ranking region: ${regionKey || '<empty>'}`);
    }
    if (
      !isRecord(region.stable_slots) ||
      !Array.isArray(region.ranked) ||
      !isRecord(region.rejected)
    ) {
      throw new Error(`incomplete ranking region: ${regionKey}`);
    }

    for (const [slot, entry] of Object.entries(region.stable_slots)) {
      const slotNumber = Number(slot);
      if (
        !Number.isInteger(slotNumber) ||
        String(slotNumber) !== slot ||
        slotNumber < 1 ||
        slotNumber > STABLE_SLOT_COUNT ||
        !NODE_KEY_PATTERN.test(keyFromEntry(entry))
      ) {
        throw new Error(`invalid stable slot in ranking region: ${regionKey}`);
      }
      decisionKeys += 1;
    }
    for (const entry of region.ranked) {
      if (!NODE_KEY_PATTERN.test(keyFromEntry(entry))) {
        throw new Error(`invalid ranked key in ranking region: ${regionKey}`);
      }
      decisionKeys += 1;
    }
    for (const key of Object.keys(region.rejected)) {
      if (!NODE_KEY_PATTERN.test(key)) {
        throw new Error(`invalid rejected key in ranking region: ${regionKey}`);
      }
      decisionKeys += 1;
    }
  }

  if (decisionKeys === 0) throw new Error('ranking contains no node decisions');
}

function buildOrdering(state, availableKeys = null) {
  validateRankingState(state);

  const rejected = new Set();
  const stableKeys = new Set();
  const order = new Map();
  let position = 0;

  const requestedOrder = Array.isArray(state.region_order)
    ? state.region_order.filter(
        (key) => typeof key === 'string' && Object.prototype.hasOwnProperty.call(state.regions, key),
      )
    : [];
  const regionKeys = [
    ...requestedOrder,
    ...REGION_ORDER.filter(
      (key) =>
        !requestedOrder.includes(key) && Object.prototype.hasOwnProperty.call(state.regions, key),
    ),
    ...Object.keys(state.regions)
      .filter((key) => !requestedOrder.includes(key) && !REGION_ORDER.includes(key))
      .sort(compareCodePoints),
  ];

  for (const regionKey of regionKeys) {
    const region = state.regions[regionKey];
    const regionRejected = rejectedKeys(region);
    for (const key of regionRejected) rejected.add(key);

    const slots = region && (region.stable_slots || region.stableSlots);
    const slotKeys = new Map();
    const reservedSlotKeys = new Set();
    if (slots && typeof slots === 'object' && regionKey !== 'other') {
      for (let slot = 1; slot <= STABLE_SLOT_COUNT; slot += 1) {
        const key = keyFromEntry(slots[String(slot)]);
        if (key && (!availableKeys || availableKeys.has(key))) {
          slotKeys.set(slot, key);
          reservedSlotKeys.add(key);
        }
      }
    }

    const regionalTail = [];
    const ranked = region && region.ranked;
    if (Array.isArray(ranked)) {
      for (const entry of ranked) {
        const key = keyFromEntry(entry);
        if (key && !regionalTail.includes(key)) regionalTail.push(key);
      }
    }

    // Rankings published before rejected nodes joined `ranked` still carry
    // their identities here. Keep them at the regional tail; `rejected` is
    // risk metadata and never a deletion list.
    for (const key of regionRejected) {
      if (!regionalTail.includes(key)) regionalTail.push(key);
    }

    if (regionKey !== 'other') {
      const usedSlotKeys = new Set();
      for (let slot = 1; slot <= STABLE_SLOT_COUNT; slot += 1) {
        let key = slotKeys.get(slot);
        if (!key) {
          key = regionalTail.find(
            (candidate) =>
              (!availableKeys || availableKeys.has(candidate)) &&
              !usedSlotKeys.has(candidate) &&
              !reservedSlotKeys.has(candidate),
          );
        }
        if (!key) {
          key = regionalTail.find(
            (candidate) =>
              (!availableKeys || availableKeys.has(candidate)) && !usedSlotKeys.has(candidate),
          );
        }
        if (!key || usedSlotKeys.has(key)) continue;
        usedSlotKeys.add(key);
        stableKeys.add(key);
        if (!order.has(key)) {
          order.set(key, position);
          position += 1;
        }
      }
    }

    for (const key of regionalTail) {
      if (!order.has(key)) {
        order.set(key, position);
        position += 1;
      }
    }
  }

  return { order, rejected, stableKeys };
}

async function operator(proxies, targetPlatform, context) {
  if (!Array.isArray(proxies)) throw new TypeError('proxy input must be an array');
  try {
    const options = operatorOptions(context);
    const rankingUrl = String(options.rankingUrl || options.url || '').trim();
    if (!rankingUrl) throw new Error('rankingUrl argument is required');

    const selected = proxies.map((proxy, originalIndex) => {
      const key = clashMetaNodeKey(proxy, context);
      return {
        proxy,
        key,
        originalIndex,
      };
    });
    const state = JSON.parse(await downloadRanking(rankingUrl, context));
    const { order } = buildOrdering(state, new Set(selected.map((entry) => entry.key)));

    selected.forEach((entry) => {
      entry.healthOrder = order.has(entry.key) ? order.get(entry.key) : Number.MAX_SAFE_INTEGER;
    });
    selected.sort(
      (left, right) =>
        left.healthOrder - right.healthOrder || left.originalIndex - right.originalIndex,
    );
    return selected.map((entry) => entry.proxy);
  } catch (error) {
    if (typeof console !== 'undefined' && typeof console.error === 'function') {
      console.error(`[node-health] ranking unavailable; preserving complete input order: ${error.message}`);
    }
    return proxies;
  }
}

if (typeof module === 'object' && module.exports) {
  module.exports = {
    NODE_HEALTH_SCHEMA_VERSION,
    REGION_ORDER,
    STABLE_SLOT_COUNT,
    buildOrdering,
    canonicalJson,
    clashMetaNodeKey,
    nodeKey,
    operator,
    sha256Hex,
    validateRankingState,
  };
}

/**
 * Stable-slot local-socks converter.
 *
 * This is a standalone reference implementation. It deliberately requires a
 * validated node-health state instead of silently reverting to sequential
 * ports.
 */
(function attachConverter(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.StableLocalSocksConverter = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createConverter() {
  const DEFAULT_START_PORT = 62000;
  const MAX_PORT = 65535;
  const REGION_PORT_BLOCK_SIZE = 200;
  const STABLE_SLOT_COUNT = 3;
  const NODE_KEY_PATTERN = /^[0-9a-f]{64}$/;

  const REGION_PORT_BLOCKS = [
    { key: 'hong-kong', matcher: /🇭🇰|\u9999\u6e2f|hong\s*kong/i, codeMatcher: /\bHK\b/ },
    { key: 'taiwan', matcher: /🇹🇼|\u53f0\u6e7e|\u53f0\u7063|taiwan|taipei|hinet/i, codeMatcher: /\bTW\b/ },
    { key: 'japan', matcher: /🇯🇵|\u65e5\u672c|japan|tokyo|osaka/i, codeMatcher: /\bJP\b/ },
    { key: 'singapore', matcher: /🇸🇬|\u65b0\u52a0\u5761|singapore/i, codeMatcher: /\bSG\b/ },
    { key: 'united-states', matcher: /🇺🇸|\u7f8e\u56fd|\u7f8e\u570b|united\s*states|los\s*angeles|san\s*francisco|seattle|new\s*york/i, codeMatcher: /\bUS\b/ },
    { key: 'south-korea', matcher: /🇰🇷|\u97e9\u56fd|\u97d3\u570b|south\s*korea|korea|seoul/i, codeMatcher: /\bKR\b/ },
    { key: 'united-kingdom', matcher: /🇬🇧|\u82f1\u56fd|\u82f1\u570b|united\s*kingdom|great\s*britain|britain|england|london|manchester/i, codeMatcher: /\bUK\b/ },
    { key: 'germany', matcher: /🇩🇪|\u5fb7\u56fd|\u5fb7\u570b|germany|deutschland|frankfurt|berlin/i, codeMatcher: /\bDE\b/ },
    { key: 'france', matcher: /🇫🇷|\u6cd5\u56fd|\u6cd5\u570b|france|paris/i, codeMatcher: /\bFR\b/ },
    { key: 'canada', matcher: /🇨🇦|\u52a0\u62ff\u5927|canada|toronto|vancouver/i, codeMatcher: /\bCA\b/ },
    { key: 'australia', matcher: /🇦🇺|\u6fb3\u5927\u5229\u4e9a|\u6fb3\u5927\u5229\u4e9e|\u6fb3\u6d32|australia|sydney|melbourne|perth|brisbane/i, codeMatcher: /\bAU\b/ },
    { key: 'other', matcher: null, unlimited: true },
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
    if (typeof TextEncoder !== 'undefined') return Array.from(new TextEncoder().encode(value));
    const bytes = [];
    for (const character of value) {
      const point = character.codePointAt(0);
      if (point <= 0x7f) bytes.push(point);
      else if (point <= 0x7ff) bytes.push(0xc0 | (point >>> 6), 0x80 | (point & 0x3f));
      else if (point <= 0xffff) {
        bytes.push(0xe0 | (point >>> 12), 0x80 | ((point >>> 6) & 0x3f), 0x80 | (point & 0x3f));
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
        const s0 = rotateRight(words[index - 15], 7) ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >>> 3);
        const s1 = rotateRight(words[index - 2], 17) ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >>> 10);
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

  function validateState(state) {
    if (
      !state ||
      state.schema_version !== 1 ||
      typeof state.version !== 'string' ||
      !state.version ||
      !state.regions ||
      typeof state.regions !== 'object'
    ) {
      throw new Error('a valid node-health current.json is required');
    }

    const regions = Object.entries(state.regions);
    if (regions.length === 0) throw new Error('ranking regions are empty');

    let decisionKeys = 0;
    for (const [regionKey, region] of regions) {
      if (!regionKey || !region || typeof region !== 'object' || Array.isArray(region)) {
        throw new Error(`invalid ranking region: ${regionKey || '<empty>'}`);
      }
      const slots = region.stable_slots || region.stableSlots;
      if (
        !slots ||
        typeof slots !== 'object' ||
        Array.isArray(slots) ||
        !Array.isArray(region.ranked) ||
        !region.rejected ||
        typeof region.rejected !== 'object' ||
        Array.isArray(region.rejected)
      ) {
        throw new Error(`incomplete ranking region: ${regionKey}`);
      }
      for (const [slot, entry] of Object.entries(slots)) {
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

  function normalizeStartPort(startPort) {
    const port = Number(startPort);
    if (!Number.isInteger(port) || port < 1 || port > MAX_PORT) {
      throw new Error(`start port must be an integer from 1 to ${MAX_PORT}`);
    }
    return port;
  }

  function validateProxies(proxies) {
    if (!Array.isArray(proxies) || proxies.length === 0) {
      throw new Error('source config has no proxies');
    }
    const names = new Set();
    proxies.forEach((proxy, index) => {
      if (!proxy || typeof proxy.name !== 'string' || !proxy.name.trim()) {
        throw new Error(`proxy ${index + 1} has no valid name`);
      }
      const original = proxy.name;
      let unique = original;
      let suffix = 2;
      while (names.has(unique)) {
        unique = `${original} #${suffix}`;
        suffix += 1;
      }
      proxy.name = unique;
      names.add(unique);
    });
  }

  function keyFromEntry(value) {
    if (typeof value === 'string') return value;
    if (!value || typeof value !== 'object') return '';
    return String(value.node_key || value.nodeKey || value.key || '');
  }

  function stateIndex(state) {
    const keyRegion = new Map();
    const stable = new Map();
    const ranked = new Map();

    for (const [regionKey, region] of Object.entries(state.regions)) {
      const rejectedEntries = region && region.rejected;
      const rejectedKeys = Array.isArray(rejectedEntries)
        ? rejectedEntries.map(keyFromEntry)
        : rejectedEntries && typeof rejectedEntries === 'object'
          ? Object.keys(rejectedEntries)
          : [];
      for (const key of rejectedKeys.filter(Boolean)) {
        keyRegion.set(key, regionKey);
      }

      const slotMap = new Map();
      const slots = region && (region.stable_slots || region.stableSlots);
      for (let slot = 1; slot <= STABLE_SLOT_COUNT; slot += 1) {
        const key = keyFromEntry(slots && slots[String(slot)]);
        if (key) {
          slotMap.set(slot, key);
          keyRegion.set(key, regionKey);
        }
      }
      stable.set(regionKey, slotMap);

      const ordered = [];
      if (region && Array.isArray(region.ranked)) {
        for (const entry of region.ranked) {
          const key = keyFromEntry(entry);
          if (key && !ordered.includes(key)) {
            ordered.push(key);
            keyRegion.set(key, regionKey);
          }
        }
      }
      // Compatibility with older ranking documents that kept rejected nodes
      // only in the metadata object. They remain usable entries at the tail.
      for (const key of rejectedKeys.filter(Boolean)) {
        if (!ordered.includes(key)) ordered.push(key);
      }
      ranked.set(regionKey, ordered);
    }

    const nodes = state.nodes && typeof state.nodes === 'object' ? state.nodes : {};
    for (const [key, node] of Object.entries(nodes)) {
      if (node && typeof node.region === 'string') keyRegion.set(key, node.region);
    }
    return { keyRegion, ranked, stable };
  }

  function fallbackRegion(name) {
    const index = REGION_PORT_BLOCKS.findIndex(
      (region) =>
        (region.matcher && region.matcher.test(name)) ||
        (region.codeMatcher && region.codeMatcher.test(name)),
    );
    return index === -1 ? 'other' : REGION_PORT_BLOCKS[index].key;
  }

  function buildRegionPortConfig(proxies, state, firstPort) {
    const index = stateIndex(state);
    const entriesByRegion = new Map(REGION_PORT_BLOCKS.map((region) => [region.key, []]));

    proxies.forEach((proxy, originalIndex) => {
      const key = nodeKey(proxy);
      const indexedRegion = index.keyRegion.get(key);
      const regionKey = entriesByRegion.has(indexedRegion) ? indexedRegion : fallbackRegion(proxy.name);
      entriesByRegion.get(regionKey).push({ key, proxy, originalIndex });
    });

    const listeners = [];
    const selectedProxies = [];
    const selectedNames = new Set();

    REGION_PORT_BLOCKS.forEach((region, regionIndex) => {
      const blockStart = firstPort + regionIndex * REGION_PORT_BLOCK_SIZE;
      const regionStableSlotCount = region.unlimited ? 0 : STABLE_SLOT_COUNT;
      const blockCapacity = region.unlimited
        ? MAX_PORT - blockStart + 1
        : REGION_PORT_BLOCK_SIZE;
      if (blockStart > MAX_PORT || blockCapacity < regionStableSlotCount) {
        throw new Error(`${region.key} port block exceeds ${MAX_PORT}`);
      }

      const available = entriesByRegion.get(region.key);
      if (available.length > blockCapacity) {
        throw new Error(
          `${region.key} has ${available.length} nodes but its port block only holds ${blockCapacity}`,
        );
      }
      const stableKeys = new Set();
      const slotMap = index.stable.get(region.key) || new Map();
      const reservedStableKeys = new Set(
        [...slotMap.values()].filter((key) => available.some((entry) => entry.key === key)),
      );
      const rankPosition = new Map(
        (index.ranked.get(region.key) || []).map((key, position) => [key, position]),
      );
      const orderedAvailable = [...available].sort((left, right) => {
        const leftRank = rankPosition.has(left.key) ? rankPosition.get(left.key) : Number.MAX_SAFE_INTEGER;
        const rightRank = rankPosition.has(right.key) ? rankPosition.get(right.key) : Number.MAX_SAFE_INTEGER;
        return leftRank - rightRank || left.originalIndex - right.originalIndex;
      });

      for (let slot = 1; slot <= regionStableSlotCount; slot += 1) {
        const requestedKey = slotMap.get(slot);
        let entry = requestedKey
          ? available.find(
              (candidate) => candidate.key === requestedKey && !stableKeys.has(candidate.key),
            )
          : undefined;
        if (!entry) {
          entry = orderedAvailable.find(
            (candidate) =>
              !stableKeys.has(candidate.key) && !reservedStableKeys.has(candidate.key),
          );
        }
        if (!entry) {
          entry = orderedAvailable.find((candidate) => !stableKeys.has(candidate.key));
        }
        if (!entry) continue;
        stableKeys.add(entry.key);
        if (!selectedNames.has(entry.proxy.name)) {
          selectedProxies.push(entry.proxy);
          selectedNames.add(entry.proxy.name);
        }
        listeners.push({
          name: `mixed-${region.key}-${slot}`,
          type: 'mixed',
          port: blockStart + slot - 1,
          proxy: entry.proxy.name,
        });
      }

      const dynamic = orderedAvailable
        .filter((entry) => !stableKeys.has(entry.key))
        .slice(0, blockCapacity - regionStableSlotCount);

      dynamic.forEach((entry, dynamicIndex) => {
        if (!selectedNames.has(entry.proxy.name)) {
          selectedProxies.push(entry.proxy);
          selectedNames.add(entry.proxy.name);
        }
        listeners.push({
          name: `mixed-${region.key}-${regionStableSlotCount + dynamicIndex + 1}`,
          type: 'mixed',
          port: blockStart + regionStableSlotCount + dynamicIndex,
          proxy: entry.proxy.name,
        });
      });
    });

    if (listeners.length !== proxies.length) {
      throw new Error(
        `converter retained ${listeners.length} of ${proxies.length} inventory nodes`,
      );
    }
    return { listeners, proxies: selectedProxies };
  }

  function convertConfig(sourceConfig, currentState, startPort = DEFAULT_START_PORT) {
    validateState(currentState);
    const proxies = (sourceConfig && sourceConfig.proxies || []).map((proxy) => ({ ...proxy }));
    validateProxies(proxies);
    const firstPort = normalizeStartPort(startPort);
    const output = buildRegionPortConfig(proxies, currentState, firstPort);

    return {
      'global-client-fingerprint': 'chrome',
      'global-ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
      'allow-lan': true,
      'bind-address': '*',
      mode: 'global',
      // OpenClash commonly exposes fake-IP answers to the router itself.
      // This independent Mihomo instance must resolve proxy server hostnames
      // through its own DNS stack or it may try to dial an unrelated 198.18/16
      // address without OpenClash's fake-IP mapping.
      dns: {
        enable: true,
        listen: '127.0.0.1:11553',
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.1/16',
        'default-nameserver': ['114.114.114.114'],
        nameserver: ['https://doh.pub/dns-query'],
      },
      listeners: output.listeners,
      proxies: output.proxies,
    };
  }

  function convertYaml(inputYaml, currentState, startPort = DEFAULT_START_PORT, yaml) {
    const codec = yaml || (typeof globalThis !== 'undefined' && globalThis.jsyaml);
    if (!codec || typeof codec.load !== 'function' || typeof codec.dump !== 'function') {
      throw new Error('js-yaml codec is required');
    }
    const state = typeof currentState === 'string' ? JSON.parse(currentState) : currentState;
    return codec.dump(convertConfig(codec.load(inputYaml), state, startPort));
  }

  return Object.freeze({
    DEFAULT_START_PORT,
    REGION_PORT_BLOCKS,
    REGION_PORT_BLOCK_SIZE,
    STABLE_SLOT_COUNT,
    canonicalJson,
    convertConfig,
    convertYaml,
    nodeKey,
    sha256Hex,
  });
});

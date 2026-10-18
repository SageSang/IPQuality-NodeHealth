# Node health integration contract

D2 (`0.4.0-dev`) keeps complete ordinary subscriptions and introduces an explicit fixed-port consumer contract. It does not migrate a running router by itself. Deployment prerequisites and rollback boundaries are in [DEPLOY_D2.md](../deploy/DEPLOY_D2.md).

## `current.json`

The anonymous endpoint remains schema 2 for the Sub-Store health operator. `stable_slots` and `ranked` contain unique connection keys; `rejected` is metadata, never a deletion list. `source.node_count` retains its connection-count meaning, with new `connection_count`, `input_count` and `alias_count` fields. The identity index keeps its original fields and adds aliases and a deterministic representative.

The public document omits credentials, raw probes, scores and private state revisions. It does not supply the new fixed-port contract. Old fixed consumers must not silently interpret it as a new map.

## `local-socks-map.json`

This anonymous endpoint projects the map in committed current state. Its schema is 1 with `consumer_contract=local-socks-explicit-v1`, `purpose=production`, approved namespace/server instance, an explicit port plan, a canonical inventory fingerprint and mapping version. Missing instance configuration, capacity failure or an unresolvable stable identity returns 503 for the map; ordinary ranking can still publish.

Every input occurrence has an entry ID. Each nonempty binding names region, port, connection key, entry ID and stable slot or dynamic index. Empty stable slots are explicit null bindings with no listener or TXT line. Dynamic ports start at base+3 regardless of holes; other has no stable slots and spans 64200-65535. Python's `port_mapping.py` is the sole allocator. Consumers validate and render, never select replacements or compact slots.

The mapping hash excludes timestamps and scores. The inventory fingerprint preserves duplicate multiplicity but ignores source ordering and YAML formatting. The fixed consumer gets this map together with its exact scan input from the private runtime bundle, never from a second live Sub-Store download. Remote endpoints may still expire between scans; snapshot consistency is not proof of ongoing remote reachability. Ordinary consumers still retain all new/unknown input entries.

## Private runtime bundles

`GET /api/v1/runtime-bundles/latest` returns a single schema-1 JSON response containing `bundle_id`, `inventory_encoding=base64`, the original inventory bytes, `inventory_sha256` and `mapping`. `/api/v1/runtime-bundles/<bundle_id>` reads a retained committed generation. `/version` advertises `runtime_bundle_schema_version=1`. The unique state revision identifies a bundle even when two scans have the same mapping hash.

Every request requires the existing nonempty `http.api_token` as a Bearer header, including loopback requests. This reuses the admin API credential, not a new read-only role. Responses are `no-store`. Missing/retired generations return 404, damaged/unreadable bundles return a safe 503, and unauthorized requests return 401. A pre-upgrade state has no bundle until a successful new maintenance scan; starting the new image does not invent input or evidence.

Private files live under the existing `data_dir/runtime-bundles` (directory 0700, files 0600), outside reports and public projections. Treat the data backup as credential-bearing. The exact input is limited to 16 MiB before scanning and the encoded bundle to 32 MiB. Files are exclusive, synced before the current commit, and checked against a committed byte digest on read. Only current and previous committed bundles are retained; uncommitted files are never served. Publication, private reads and cleanup share a lock. Cleanup failures are logged safely without blocking startup or turning a successful publication into a failed scan.

## Publication, snapshots, and reports

The state layout remains schema 2; the current evidence/scoring policy is **2**, while raw probe/risk contracts remain 1. Upgrading from policy 1 discards old scores, cached detection results, health days and promotion history. It preserves node identities, placement, cooldowns and the independent subscription preferences. The first successful maintenance scan audits every available node and preserves surviving slot/ranked/other positions, so existing port bindings remain stable for unchanged inventory. Missing identities leave holes; new identities append. Unavailable or incomplete nodes retain a durable pending-audit marker and are retried when available. Later maintenance scans resume normal replacement/promotion rules. A full scan supplies fresh scores, not six days of health qualification. Do not use `rebuild` merely to refresh evidence: it intentionally reallocates slots.

The reset is transactional with publication. A failed scan leaves the committed generation untouched. A policy-1 binary rejects policy-2 state; rolling back requires the matching pre-upgrade data backup, not just an older image. Historical report archives remain unchanged. The older pre-policy-1 M1 handling is separate; this upgrade does not carry it forward or create/extend grace entitlements.

Snapshots, maps and report archives are prepared before `current.json` selects the committed revision. Latest views recover from that revision. NAS reports and regional/all TXT are **targets**, not proof of router application. Temporary audits are proposals and cannot pass the production map validator. The router's local `applied.json` and associated exports are its application receipt; no network receipt/control plane is introduced.

AI points describe site/region probes, not account or conversation success. ChatGPT uses one 12-point site/support observation plus up to 3 points of independent same-service-egress geography; Claude contributes up to 10. Duplicate quick/full observations and legacy Yes/Native strings do not create additional evidence. Error responses and unknown risk flags cannot become positive evidence.

Health/error APIs retain bounded codes, phase and diagnostic ID. Legacy report errors receive safe read projections; original archives are not overwritten. Retry progress explicitly reports waiting-retry/rechecking, retry round, pending nodes and next_retry_at; percent_scope is phase.

## Detection diagnostics and policy 2

Hosting/server, proxy and VPN flags retain soft penalties and prevent a clean A, but cannot by themselves produce C or a synthesized high-risk score. Confirmed Tor, DNSBL at the configured threshold, two independent high-risk sources and three independent abuse reports still trigger C. Generic and Claude egress evidence remain separate. Flag-derived scores require all expected boolean fields; missing, string or numeric pseudo-booleans remain unknown. A positive hosting flag or a country/ASN-only response does not qualify as a complete risk provider. Aliases of the same provider count once.

`probe_diagnostics` in private reports distinguishes `provider_invalid_auth` (401), `provider_forbidden` (403), rate limits, partial 200 responses and complete capabilities. It includes the last checked/success times and present/missing flags, without credentials, query strings or raw responses. `successes` counts accepted JSON HTTP responses; `complete_responses` counts usable responses. Counters reset each scan; last-success time is process-local. A 403 alone does not prove an account problem. Provider credentials and subscriptions still need operational verification; this code does not fix a denied account. Existing cache, retry-after, bounded backoff and request budgets remain active.

A rotated connection that fails the existing quick retries defers its deep audit. The pending marker survives restart and forces a fresh audit on recovery; old connection reputation is never inherited. In ordinary promotion, an incumbent without fresh valid evidence is skipped while other eligible slots can still be compared. Regional `promotion_diagnostics` identifies cooldown, blocked slots, missing current evidence, insufficient health/common days, grade regression and failed margin checks. The thresholds remain 6 health days, 3 common valid days, 15 points, 7 cooldown days and at most one ordinary promotion per region/run.

Authenticated `GET /api/v1/nodes` adds `available` and `score_provenance`: observed score, ranking-score source/day, scoring-policy version, evidence validity, quick/full/Claude observation times, and Claude intelligence cache/time. Components describe this round's observation; if the ranking score is retained, components need not sum to that retained score. A cached provider result is not a new day's qualifying observation. These fields stay out of the anonymous ranking projection.

## Stable node identity

Connection hashing remains credential-sensitive and display-name-independent. One connection is probed once and can occupy at most one stable slot, while every alias occurrence remains in ordinary subscriptions and explicit maps. Existing representative aliases are preferred; new choices are deterministic. All phases use one effective region before outage grouping and audit selection.

Exact keys win; connection rotation may inherit a slot only through mutually unique, safe identity reconciliation. Missing source metadata still supports unique region/name fallback. Known conflicting sources or ambiguous names are never guessed. Normalized/default region rules come from `node_health/region_rules.json` and generated JS; custom classifications travel with the authoritative identity/map. Region-rule changes do not silently move existing fixed identities.

## Sub-Store

Use a complete `inventory` collection without the health operator. Put `health-ranking-operator.js` last in the otherwise complete `healthy` chain, with `rankingUrl` pointing to `/current.json`; retain `target=ClashMeta&noCache=true`. A stable connection contributes one representative before the dynamic tail; additional aliases cannot displace other stable representatives. Failure preserves the full original input.

The ClashMeta producer can remove underscore metadata. Adding `_nh_slot` to an ordinary proxy object is therefore not a guaranteed fixed-port transport. OpenWrt consumes the NAS private snapshot containing the exact inventory used for its map. Sub-Store cache-busting parameters do not provide historical snapshots.

## Subscription pin preferences

The service and the Sub-Store operator support a shared, ordered list of up to
three pinned connections for ordinary `healthy` subscriptions. Pins are global
within that subscription: a selected node can move ahead of the first region.
Every request first computes the existing automatic order, then moves one
representative occurrence per pin to the front. Remaining occurrences preserve
their relative order, including aliases and unknown nodes. A stable connection
uses its existing representative. Pins never filter or duplicate proxies.

For automatic order `A B C D E`, with stable slots `1=A, 2=B, 3=C`, pinning `E`
produces `E A B C D`; pinning `B` produces `B A C D E`. The stored slots remain
`1=A, 2=B, 3=C` in both cases. Scoring, health qualifications, probe selection,
cooldowns, normal slot replacement, fixed ports and SOCKS exports are independent
of preferences. A failed probe does not revoke a pin. Missing nodes are skipped,
but their preferences are retained. Exact connection keys survive display-name
changes; rotation uses the existing mutually unique/source-compatible identity
rules. Missing or ambiguous identities are visible in the admin response.

All three management routes require a **nonempty** `http.api_token` and its
`Authorization: Bearer ...` header, even on loopback:

| Method and path | Response / operation |
| --- | --- |
| `GET /api/v1/nodes` | Names, keys, regions, scores, confidence, automatic slots and pin positions |
| `GET /api/v1/subscription-preferences` | Saved keys, resolved keys, per-pin status, revision and ETag |
| `PUT /api/v1/subscription-preferences` | Replace the ordered list; an empty list restores automatic order |

Node positions describe **published connection representatives**, not every
alias or a client's filtered live input. `stable_slot` and `pin_position` are
different fields. In the preference response, `pinned_nodes` are the saved keys;
`resolved_pinned_nodes` are their current matches. When a saved key has rotated,
callers can submit that saved key or the resolved key on their next edit. A
changed list canonicalizes proven matches to current keys; callers should use
the returned saved list and ETag for the next edit. No proxy credentials are
returned by these routes.

Example (use the ETag returned by GET, not a hardcoded revision):

```sh
curl -i "$NODE_HEALTH_URL/api/v1/subscription-preferences" \
  -H "Authorization: Bearer $NODE_HEALTH_TOKEN"

curl -i -X PUT "$NODE_HEALTH_URL/api/v1/subscription-preferences" \
  -H "Authorization: Bearer $NODE_HEALTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "0"' \
  --data '{"pinned_nodes":["<node_key returned by GET /api/v1/nodes>"]}'
```

PUT accepts only `pinned_nodes`, with 0–3 unique keys. Unknown new keys, duplicate
keys or extra fields return 422; malformed JSON/ETags return 400; a missing
If-Match returns 428; a stale revision returns 412. Missing/incorrect tokens
return 401. An unchanged list at the current revision succeeds without creating
a new revision. On an uncertain response, GET the saved settings before retrying.

Preferences are atomically stored in `data_dir/preferences.json`, independently
of scan state, under the single service process's short preference lock. The file
also retains an allowlisted identity population to prevent ambiguous rotation
matches; it contains no proxy configuration or credentials. Back it up with the
data directory. It is neither cleared on restart nor written by a scan. An absent
file means no pins; malformed/unreadable preferences return a safe admin 503 and
are never silently reset. Restore a known-good copy if necessary.

`/current.json` adds `subscription_preferences` at response time, with its own
schema 1, status, revision, modification time and resolved `pinned_nodes`. All
existing schema-2 ranking fields keep their original meaning. A preference PUT
does not rewrite the stored `current.json`, `state.json`, reports, runtime bundle
or map; health timestamps and ranking versions do not change. `/version`
advertises `subscription_preferences_schema_version=1`.

After a successful PUT, newly started ranking/subscription requests see the new
preferences without waiting for a scan. The client must refresh its subscription;
the API does not claim to have switched its active proxy. Already-running reads
may finish with the previous revision. Responses use `Cache-Control: no-store`,
and the operator downloads fresh ranking on every execution. Keep it last in the
processing chain, and check downstream caches or client-side sorting. Sub-Store's
outer `noCache=true` does not disable arbitrary script-result caches.

Upgrade the service and operator together. Old operators ignore the additive
field; new operators accept old servers without preferences. Malformed optional
preferences fall back to automatic order; an unavailable ranking retains the
existing complete-input fallback. Clearing the list restores automatic ordering
without resetting health history. This change requires no OpenWrt updater,
fixed-port converter or runtime-profile upgrade.

## OpenWrt poller

Install the matching shell entry points, `runtime-controller.mjs`, `convert-ranking.mjs`, strict converter, Node and js-yaml. A working kernel `flock` implementation and local process proof (ubus/procd, or an explicit PID file with the same core and -f path) are required. Missing dependencies fail before configuration/service changes; the two entry points share one inherited-descriptor lock released on process exit, including SIGKILL.

The poller performs local pending recovery and self-healing before upstream backoff or network downloads. Set `RUNTIME_BUNDLE_URL` and `RUNTIME_TOKEN_FILE`; the latter must be a regular 0600 file owned by the runtime user (root in the documented installation), containing the NAS API token. Download uses a private header file, ignores curl startup configuration, rejects redirects and accepts only HTTP 200. Use HTTPS or a trusted restricted LAN; Bearer authentication alone does not encrypt HTTP. URLs cannot include credentials, queries or fragments.

The received inventory byte hash, schema, purpose, approved namespace/instance/plan, age, exact fingerprint and binding completeness are all checked before applying. No failure falls back to a live `SOURCE_URL` or `RANKING_URL`; those legacy values are ignored by this poller. Interrupted private downloads are removed on the next poll after local recovery. Do not keep the old sequential updater running in parallel.

Source/profile mismatch is visible via a safe `CACHE_DIR/last-error.json` code and phase. It does not authorize an unreviewed profile, source switch or a weaker fallback. Profile/DNS/IPv6/LAN/core choices remain those reviewed for the actual installation.

## Stable-port converter

The converter accepts the new explicit map and an approved runtime profile. It keeps the configuration shell, safely remaps supported references and rejects unresolved/unsupported dependencies. The standalone runner emits a private candidate plus a non-credential manifest and target exports; it does not apply a service configuration.

The controller preserves the first verified legacy baseline, stages paired configuration/core/manifest/TXT, journals pending work and commits only through applied.json after process and SOCKS readiness checks. Exports failing to restore cannot prevent attempting service restoration. A successful restart command without a replaced process is not readiness. Same runtime configuration plus healthy listeners does not restart; a stopped service still recovers. HY2 hopping retains a still-valid old concrete port rather than restarting on random producer choices.

New configuration application and rollback can interrupt existing connections. Local handshake tests do not prove remote proxy egress; retained unavailable nodes are not deleted merely to make application tests pass.

For the superseded v0.3 integration details, use the [immutable historical document](https://github.com/SageSang/IPQuality-NodeHealth/blob/e947801f711a04096aa842b87dd41dc22a777735/integrations/README.md). Its old sequential/advanced interfaces are not D2 deployment instructions.

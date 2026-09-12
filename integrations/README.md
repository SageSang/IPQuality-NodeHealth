# Node health integration contract

D2 (`0.4.0-dev`) keeps complete ordinary subscriptions and introduces an explicit fixed-port consumer contract. It does not migrate a running router by itself. Deployment prerequisites and rollback boundaries are in [DEPLOY_D2.md](../deploy/DEPLOY_D2.md).

## `current.json`

The anonymous endpoint remains schema 2 for the Sub-Store health operator. `stable_slots` and `ranked` contain unique connection keys; `rejected` is metadata, never a deletion list. `source.node_count` retains its connection-count meaning, with new `connection_count`, `input_count` and `alias_count` fields. The identity index keeps its original fields and adds aliases and a deterministic representative.

The public document omits credentials, raw probes, scores and private state revisions. It does not supply the new fixed-port contract. Old fixed consumers must not silently interpret it as a new map.

## `local-socks-map.json`

This anonymous endpoint projects the map in committed current state. Its schema is 1 with `consumer_contract=local-socks-explicit-v1`, `purpose=production`, approved namespace/server instance, an explicit port plan, a canonical inventory fingerprint and mapping version. Missing instance configuration, capacity failure or an unresolvable stable identity returns 503 for the map; ordinary ranking can still publish.

Every input occurrence has an entry ID. Each nonempty binding names region, port, connection key, entry ID and stable slot or dynamic index. Empty stable slots are explicit null bindings with no listener or TXT line. Dynamic ports start at base+3 regardless of holes; other has no stable slots and spans 64200-65535. Python's `port_mapping.py` is the sole allocator. Consumers validate and render, never select replacements or compact slots.

The mapping hash excludes timestamps and scores. The inventory fingerprint preserves duplicate multiplicity but ignores source ordering and YAML formatting. A renamed, new or rotated entry requires a newly coherent map; the fixed consumer retains its last verified configuration until the next successful scan. Ordinary consumers still retain all new/unknown input entries.

## Publication, snapshots, and reports

The state layout remains schema 2. Evidence policy/probe versions are independent; legacy health qualifications are re-established without clearing stable identities, other order or cooldowns. Original raw facts remain available for traceability. A bounded one-time M1 migration exception can preserve original earned failure protection without adding score or promotion evidence.

Snapshots, maps and report archives are prepared before `current.json` selects the committed revision. Latest views recover from that revision. NAS reports and regional/all TXT are **targets**, not proof of router application. Temporary audits are proposals and cannot pass the production map validator. The router's local `applied.json` and associated exports are its application receipt; no network receipt/control plane is introduced.

AI points describe site/region probes, not account or conversation success. ChatGPT uses one 12-point site/support observation plus up to 3 points of independent same-service-egress geography; Claude contributes up to 10. Duplicate quick/full observations and legacy Yes/Native strings do not create additional evidence. Error responses and unknown risk flags cannot become positive evidence.

Health/error APIs retain bounded codes, phase and diagnostic ID. Legacy report errors receive safe read projections; original archives are not overwritten. Retry progress explicitly reports waiting-retry/rechecking, retry round, pending nodes and next_retry_at; percent_scope is phase.

## Stable node identity

Connection hashing remains credential-sensitive and display-name-independent. One connection is probed once and can occupy at most one stable slot, while every alias occurrence remains in ordinary subscriptions and explicit maps. Existing representative aliases are preferred; new choices are deterministic. All phases use one effective region before outage grouping and audit selection.

Exact keys win; connection rotation may inherit a slot only through mutually unique, safe identity reconciliation. Missing source metadata still supports unique region/name fallback. Known conflicting sources or ambiguous names are never guessed. Normalized/default region rules come from `node_health/region_rules.json` and generated JS; custom classifications travel with the authoritative identity/map. Region-rule changes do not silently move existing fixed identities.

## Sub-Store

Use a complete `inventory` collection without the health operator. Put `health-ranking-operator.js` last in the otherwise complete `healthy` chain, with `rankingUrl` pointing to `/current.json`; retain `target=ClashMeta&noCache=true`. A stable connection contributes one representative before the dynamic tail; additional aliases cannot displace other stable representatives. Failure preserves the full original input.

The ClashMeta producer can remove underscore metadata. Adding `_nh_slot` to an ordinary proxy object is therefore not a guaranteed fixed-port transport. OpenWrt's D2 consumer reads the explicit map and matching inventory independently.

## OpenWrt poller

Install the matching shell entry points, `runtime-controller.mjs`, `convert-ranking.mjs`, strict converter, Node and js-yaml. A working kernel `flock` implementation and local process proof (ubus/procd, or an explicit PID file with the same core and -f path) are required. Missing dependencies fail before configuration/service changes; the two entry points share one inherited-descriptor lock released on process exit, including SIGKILL.

The poller performs local pending recovery and self-healing before upstream backoff or network downloads. It downloads map, inventory, map and verifies namespace/instance, schema, purpose, approved plan, age, exact fingerprint and binding completeness. URL cache-busting is not treated as a content/version lock. Do not keep the old sequential updater running in parallel.

Source/profile mismatch is visible via a safe `CACHE_DIR/last-error.json` code and phase. It does not authorize an unreviewed profile, source switch or a weaker fallback. Profile/DNS/IPv6/LAN/core choices remain those reviewed for the actual installation.

## Stable-port converter

The converter accepts the new explicit map and an approved runtime profile. It keeps the configuration shell, safely remaps supported references and rejects unresolved/unsupported dependencies. The standalone runner emits a private candidate plus a non-credential manifest and target exports; it does not apply a service configuration.

The controller preserves the first verified legacy baseline, stages paired configuration/core/manifest/TXT, journals pending work and commits only through applied.json after process and SOCKS readiness checks. Exports failing to restore cannot prevent attempting service restoration. A successful restart command without a replaced process is not readiness. Same runtime configuration plus healthy listeners does not restart; a stopped service still recovers. HY2 hopping retains a still-valid old concrete port rather than restarting on random producer choices.

New configuration application and rollback can interrupt existing connections. Local handshake tests do not prove remote proxy egress; retained unavailable nodes are not deleted merely to make application tests pass.

For the superseded v0.3 integration details, use the [immutable historical document](https://github.com/SageSang/IPQuality-NodeHealth/blob/e947801f711a04096aa842b87dd41dc22a777735/integrations/README.md). Its old sequential/advanced interfaces are not D2 deployment instructions.

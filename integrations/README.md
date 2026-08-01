# Node health integration contract

This directory contains the integration boundary between the Synology
`node-health` service, Sub-Store, and the existing OpenWrt `local-socks`
instance. None of these files contains a subscription URL or credential.

The recommended deployment is the simplified path documented in
`deploy/DEPLOY_SIMPLE.md`: Sub-Store consumes `current.json`, and OpenWrt
continues to consume only the resulting `healthy` subscription with the
existing `rule_conf` converter. The direct OpenWrt poller and stable-port
converter below are retained as an optional advanced design and are not part
of the current rollout.

## `current.json`

The Sub-Store operator, and optionally the advanced stable-port converter,
consume the same document:

```json
{
  "schema_version": 1,
  "version": "20260723T215800Z-a1b2c3d4",
  "generated_at": "2026-07-24T05:58:00+08:00",
  "mode": "maintenance",
  "region_order": [
    "hong-kong", "taiwan", "japan", "singapore", "united-states",
    "south-korea", "united-kingdom", "germany", "france", "canada",
    "australia", "other"
  ],
  "regions": {
    "united-states": {
      "stable_slots": {
        "1": "2af9...64 hex characters...",
        "2": "88d1...64 hex characters..."
      },
      "ranked": ["8a02...", "fa93..."],
      "rejected": {
        "60aa...": "country-mismatch:JP!=US"
      }
    }
  }
}
```

The HTTP `/current.json` response intentionally contains only this integration
surface. Detailed node names, scores, stable status, exit IPs, and raw probe
results stay in the private persisted state and reports; Sub-Store and OpenWrt
must not depend on those private fields.

After a valid document is loaded, `regions.*.stable_slots` plus
`regions.*.ranked` form the complete allow-list. Explicitly rejected keys and
keys missing from that allow-list are removed. An invalid or unavailable
document makes the collection request fail closed; it must never cause
Sub-Store to label the unfiltered source as healthy.

A valid document has at least one region. Every region payload must be an
object containing an object `stable_slots`, an array `ranked`, and an object
`rejected`. Individual regions may contain no nodes, but the document as a
whole must contain at least one node key in one of those three decision sets.
An explicit all-rejected document is valid and intentionally returns an empty
proxy array. Current Sub-Store collection downloads reject a zero-proxy
artifact and normally answer with an HTTP error, so direct clients may retain
their own previous cache. OpenWrt avoids that ambiguity by filtering the full
inventory locally and can publish a deliberate zero-listener config. An empty
`regions` object or an all-empty shell is invalid.

Fetch, validation, missing-argument, and identity-drift failures are
fail-closed: the Script Operator throws, so Sub-Store must not expose the
unfiltered source as a healthy subscription. Direct clients normally keep
their own prior subscription cache. The OpenWrt poller has an independent
state-validation layer and keeps its last applied configuration when a new
pair cannot be validated.

After a state has passed validation, its allow-list is strict. A non-empty
allow-list that matches zero input proxies throws an identity-drift error; an
intentional all-rejected state has an empty allow-list and returns `[]`.

Stable-slot membership is authoritative over a transient rejection such as
`quick_unavailable` while its consecutive-failure grace period remains. At the
configured threshold, or immediately when the identity disappears from the
full inventory, node-health removes/replaces that key in `stable_slots`.
Hard-danger removal uses the same published-state transition.

`version` is an opaque, non-empty string. The OpenWrt poller compares it for
equality and writes it only after a successful atomic apply.

## Publication, snapshots, and reports

`data/current.json` is the durable commit selector for a published ranking.
`data/state.json` is the latest working state, while
`data/state-snapshots/<version>.json` is the immutable state paired with a
specific ranking version. The service keeps the newest three snapshots. On
restart it loads only the snapshot whose version matches `current.json`, so an
interruption before the final current-file replacement cannot advance stable
slots without advancing the public ranking.

Mutable JSON and Markdown files are written through atomic file replacement;
immutable alert history is created exclusively. The files are not one
cross-file transaction. Publication prepares reports, then writes the
versioned state snapshot and `state.json`, and replaces `current.json` last.
Consumers therefore treat `current.json` as authoritative and use the embedded
`version` when correlating a report. A rare interruption before the final
replacement can leave a newer report on disk while the authoritative ranking
remains old; reports are observability artifacts, not recovery state.

The dated `reports/YYYY-MM-DD.md` and `.json` files describe the latest run
written for that date and are retained for the configured number of days.
Each report node has a normalized `geo` object for its observed exit IP,
country, subdivision, city, ASN, organization, timezone, coordinates, source,
observation time, and fresh/cached status. These report-only fields are not
part of `current.json` and are never consumed for ranking recovery.
Every successful scheduled publication also writes the current regional SOCKS5
lists to `reports/local-socks/latest/<region>.txt` and archives the same files
under `reports/scheduled/YYYY/MM/DD/<version>/local-socks/`. Subscription audits
write their lists beside the audit report in its `local-socks/` directory.
Each line uses `socks5://<advertise-host>:<port>{<real source node name>}`;
internal position labels such as `dynamic-001` are never used as proxy names.
`reports/alerts/latest-run.md` is refreshed for every publication.
`slot-changes-latest.md` is created initially and thereafter changes only when
a stable identity changes. Each such change also creates an immutable
`alerts/YYYY-MM-DD-<version>.md` history file; daily-report retention does not
delete those alert-history files.

## Stable node identity

All components calculate `node_key` identically:

1. Normalize the Sub-Store internal object with the ClashMeta producer so the
   operator hashes the same shape exported by `inventory`.
2. Remove only the top-level `name` field and top-level fields whose names
   begin with `_`.
3. If a port-hopping `ports` range exists, omit the producer's randomly chosen
   concrete `port`; the durable range remains part of the identity.
4. Sort object keys recursively by Unicode code point. Preserve array order.
5. Serialize compact JSON as UTF-8 without escaping non-ASCII characters.
6. Return the full lowercase SHA-256 hexadecimal digest.

Names therefore can change without moving a slot. Any transport or credential
change produces a new identity and requires a fresh health decision. Proxy
objects must come from the same normalized Sub-Store `inventory` collection;
otherwise YAML parsers can disagree about scalar types.

The cross-language fixed vector is:

```text
canonical JSON: {"network":"ws","port":443,"server":"example.com","tls":true,"type":"vmess","uuid":"secret","ws-opts":{"headers":{"Host":"edge.example.com"},"path":"/ws"}}
SHA-256:        1811ab43423a2b26e7f6ee03483b1d19a566f3929e30e593b6defac6071a2a92
```

## Sub-Store

Install `sub-store/health-ranking-operator.js` as the last Script Operator on
the `healthy` collection. Configure the operator's injected `$arguments` with:

```json
{
  "rankingUrl": "http://SYNOLOGY_LAN_IP:18887/current.json"
}
```

The script also accepts `url`. It adds Sub-Store's `#noCache` download option,
so the small status document is fetched whenever the operator runs. Keep an
unmodified `inventory` collection for the scanner and use `healthy` for every
client subscription. Both download URLs must request Clash YAML and bypass the
default upstream-resource cache:

```text
http://SYNOLOGY_LAN_IP:3001/download/collection/inventory?target=ClashMeta&noCache=true
http://SYNOLOGY_LAN_IP:3001/download/collection/healthy?target=ClashMeta&noCache=true
```

The scanner's `SUB_STORE_INVENTORY_URL` and the OpenWrt poller's `SOURCE_URL`
must both use the first URL. Only ordinary subscription clients use the second
URL; pointing either scanner or OpenWrt source at `healthy` creates an
unnecessary filtered feedback path and prevents local recovery of omitted
nodes.

In the current Sub-Store implementation, every `/download/collection` request
runs `produceArtifact`, including the Script Operator. Source-resource
downloads can otherwise remain cached for one hour; `noCache=true` is what
forces those sources to refresh. Before rollout, confirm this contract against
the installed Sub-Store version: request the same `healthy` URL twice and
verify in its logs that the operator ran twice, then publish a real slot change
and verify the returned first three regional nodes match `current.json`.

The operator always derives identities through fixed ClashMeta internal
production, regardless of the client target requested from Sub-Store. If a
non-empty ranking allow-list matches zero source identities, it throws an
identity-drift error instead of silently emitting the unfiltered source.

## OpenWrt poller

Copy `openwrt/check-ranking.sh`, `openwrt/apply-ranking.sh`,
`openwrt/convert-ranking.mjs`, and `openwrt/service-lib.sh` to
`/etc/local-socks/`. Copy `openwrt/local-socks.init` to
`/etc/init.d/local-socks`, then copy `openwrt/node-health.env.example` to
`/etc/local-socks/node-health.env`.
Protect the environment file with mode `0600` and make the script executable.
Run it every ten minutes:

```cron
*/10 * * * * /etc/local-socks/check-ranking.sh
```

`APPLY_COMMAND` is an executable adapter with this interface:

```text
apply-command INVENTORY_YAML CURRENT_JSON VERSION
```

The supplied `apply-ranking.sh` implements this interface. It invokes
`convert-ranking.mjs` and the stable converter, runs
`clash_meta -t -f CANDIDATE`, atomically replaces `config.yaml`, restarts
`local-socks`, checks readiness, and rolls back on failure. Its paths are
configured in the private environment file.

The service copies the current OpenClash core to the independently named
`/etc/local-socks/bin/mihomo-local-socks` executable before starting. This
prevents an OpenClash core restart or process-name cleanup from terminating the
local SOCKS runtime, and raises its file-descriptor limit for large listener
sets. Runtime checks use the actual procd instance state plus a live listener;
when local artifacts are coherent, a stopped runtime is recovered locally
without downloading or reordering the subscription.

The same conversion writes every region TXT file into a staging directory.
Only after the new Mihomo process is ready does the apply script replace
`/root/local-socks`; a TXT publication failure rolls the service config back
as well. `ADVERTISE_HOST` controls the LAN address written into those files.
The text inside braces is the exact source proxy name bound to that listener,
for example `socks5://192.0.2.4:62000{🇭🇰 Hong Kong 07}`.

`NODE_PATH` defaults to module locations outside the TXT export directory. When the
installed `js-yaml` cannot be resolved through it, set `JS_YAML_PATH` to the
absolute module entry point and verify it with Node before enabling cron.
The apply script rejects any config or dependency path overlapping
`EXPORT_DIR`, because that directory is atomically replaced on publication.

The poller downloads `current.json`, then the complete ClashMeta `inventory`, then
`current.json` again. It applies only when both versions match. It uses
`flock`, with a reboot-cleared `/tmp` directory-lock fallback, and persists
exponential backoff. The inventory request appends `_node_health_version=<encoded current version>`
and sends `Cache-Control: no-cache` plus `Pragma: no-cache`. This ties the
request URL to the ranking version and avoids intermediary reuse; current
Sub-Store still reruns `produceArtifact` for each collection request, while the
required `noCache=true` query refreshes its upstream sources. `SOURCE_URL`
must include `target=ClashMeta&noCache=true` and must not contain a URL
fragment; ordinary query parameters are supported.

Even when the ranking version is unchanged, the poller verifies the applied
config SHA-256, service status, and all regional TXT files before skipping.
Manual overwrite, a stopped service, or missing exports triggers a repair
apply without deleting `applied.version`.

The ranking version is a stable fingerprint of the runtime projection. A daily
scan may refresh scores and reports without changing this version, so an
unchanged ranking does not restart `local-socks`; a changed node set, slot,
dynamic order, or rejection set does.

## Stable-port converter

`local-socks/convert-any-proxy-to-local-socks-stable.js` is a standalone
replacement/reference for the converter in `rule_conf`. Its API is:

```js
converter.convertConfig(sourceConfig, currentState, 62000)
converter.convertYaml(sourceYaml, currentState, 62000, yamlCodec)
converter.nodeKey(proxy)
```

For every fixed region, slots 1 through 3 map to `base + slot - 1`.
Candidates start at `base + 3`; empty stable slots remain empty and never
shift another slot. Explicitly rejected keys are omitted. Unknown proxies are
also omitted after a valid state is loaded. A state fetch/validation failure is
handled before conversion and leaves the last working OpenWrt config active.
The heterogeneous `other` region has no stable slots and starts
at its block base (`64200` with the default start port).

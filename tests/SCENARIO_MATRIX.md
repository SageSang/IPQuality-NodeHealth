# Node-health functional scenario matrix

This matrix defines the deployment-blocking behavior of schema v2. The
existing `rule_conf` pre-filter is outside this boundary: its output is the
authoritative inventory consumed by node-health. From that point onward,
health processing may reorder nodes but may not remove them.

## Identity and connection rotation

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| ID-00 | Source/original-name metadata contains full-width characters or irregular whitespace | Normalize source/name deterministically and publish only hashes plus non-secret labels | `test_inventory_builds_normalized_non_secret_logical_identity_metadata` |
| ID-01 | Connection key is unchanged while display/source metadata changes | Exact connection identity wins; no rotation event | `test_exact_connection_key_wins_without_rotation_event`, `testExactConnectionIdentityPrecedesLogicalSourceMismatch` |
| ID-02 | Server/port/credential changes with the same source and original name | Stable slot and baseline move to the new key; old risk/IP evidence is cleared | `test_source_and_name_rotation_inherits_slot_but_not_connection_reputation` |
| ID-03 | Source metadata is absent but region plus exact name is unique | Safely inherit the old position | `test_region_unique_name_rotation_works_without_source_metadata`, `test_rotated_connection_is_forced_into_same_round_full_audit` |
| ID-04 | Only case/Unicode/whitespace-normalized regional name is unique | Safely inherit by normalized name | `test_normalized_unique_name_matches_case_and_whitespace_change`, `testNormalizedUniqueNameFallbackAndAmbiguityGuard` |
| ID-05 | One old name maps to multiple new connections, or both sides are duplicated | Do not guess; treat them as unmatched nodes | `test_ambiguous_duplicate_names_are_not_automatically_inherited`, `test_one_old_name_does_not_guess_between_two_new_connections`, `testNormalizedUniqueNameFallbackAndAmbiguityGuard` |
| ID-06 | Same regional name exists under two known, different sources | Never inherit across sources | `test_known_different_sources_never_inherit_by_name_fallback`, `testLogicalIdentityNeverCrossesKnownSources` |
| ID-07 | Multiple uniquely named connections rotate together | Reconcile every pair one-to-one and preserve slot/cooldown timestamps | `test_multiple_source_tagged_rotations_reconcile_one_to_one` |
| ID-08 | New region classification disagrees with a reconciled stable identity | Preserve the stable identity's previous region | `test_reconciled_slot_keeps_previous_region_when_new_classification_disagrees` |
| ID-09 | A stable connection rotates | Keep the same slot, emit no slot-change alert, and force a full audit in that run | `test_rotated_stable_connection_keeps_slot_and_is_forced_into_full_audit` |
| ID-10 | A dynamic connection rotates outside the normal daily sample | Force a full audit in that run | `test_rotated_connection_is_forced_into_same_round_full_audit` |
| ID-11 | A schema-v1 state is present | Do not attempt compatibility migration; rebuild schema-v2 state | `test_schema_v1_state_is_intentionally_not_reconciled` plus storage schema checks |

## Fixed slots, risk, and availability

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| SL-01 | Three or more safe usable nodes, no redline | Preserve healthy fixed identities | `test_maintenance_preserves_healthy_slots_and_replaces_only_failed_slot` |
| SL-02 | A fixed node hits a confirmed redline | Replace it immediately with the best safe dynamic node | `test_maintenance_quality_redline_replaces_only_one_slot` |
| SL-03 | Two fixed nodes hit redlines together | Replace only those slots with the best two dynamic candidates | `test_two_simultaneous_redlines_replace_only_their_slots_with_best_dynamic_nodes` |
| SL-04 | Redline occurs during an active quality-promotion cooldown | Risk replacement still executes immediately | `test_redline_replacement_ignores_active_quality_promotion_cooldown` |
| SL-05 | Fixed node fails one or two consecutive quick-scan rounds | Preserve its slot and wait for recovery | `test_unavailable_stable_is_replaced_only_after_three_consecutive_failures`, `test_maintenance_keeps_temporarily_unavailable_stable_slot` |
| SL-06 | Fixed node fails the third consecutive round | Replace it with the best candidate and move it to the regional tail | `test_three_consecutive_unavailable_runs_replace_stable_and_move_it_to_tail` |
| SL-07 | Dynamic node reaches three failures | Sort it behind nodes with fewer consecutive failures | `test_three_failures_move_dynamic_node_behind_more_recent_failures` |
| SL-08 | Any failed node becomes reachable | Reset its consecutive-failure counter to zero | `test_reachable_stable_node_resets_unavailable_counter`, `test_dynamic_unavailable_counter_is_consecutive_and_resets_on_recovery` |
| SL-09 | Fewer than three safe nodes | Rerank the whole region by availability, risk, score, and latency; fill as many slots as possible | `test_degraded_rerank_fills_three_slots_and_keeps_rejected_nodes`, `test_three_failure_fallback_still_fills_slots_when_safe_nodes_are_insufficient` |
| SL-10 | Every node is risky | Keep every node and put the least risky/highest-quality node first | `test_all_rejected_nodes_fill_slots_by_risk_then_score` |
| SL-11 | Every node is unavailable | Still publish and fill slots from the complete regional inventory | `test_first_rebuild_publishes_even_when_all_nodes_are_unavailable` |
| SL-12 | Region contains 0, 1, 2, or 3 total nodes | Create exactly `min(3, total)` unique slots and lose no node | `test_region_with_fewer_than_three_nodes_uses_every_node_once` |
| SL-13 | Node disappears from the authoritative inventory | Remove it immediately and fill the vacancy if possible | `test_missing_inventory_node_is_immediately_replaced`, `test_missing_entire_region_releases_absent_slots_in_maintenance` |

## Quality promotion and cooldown

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| PR-01 | Candidate leads by at least 10 points today and yesterday and has two distinct-day passes | Promote at most one candidate | `test_default_promotion_requires_two_distinct_days_and_ten_point_margin` |
| PR-02 | Current margin is sufficient but previous-day margin is below 10 | Do not promote | `test_promotion_requires_previous_day_margin_even_when_current_margin_is_large` |
| PR-03 | Same-day maintenance is run repeatedly | Do not increment the distinct-day pass count | `test_full_passes_count_distinct_calendar_days_not_same_day_reruns` |
| PR-04 | Candidate or compared stable node lacks fresh, high-confidence evidence | Do not promote | `test_promotion_waits_when_the_weakest_stable_slot_lacks_fresh_high_evidence`, `test_promotion_requires_fresh_usable_evidence_from_the_candidate` |
| PR-05 | Quality-promotion cooldown is just under or exactly two days | Block just under two days; allow at the exact boundary | `test_quality_promotion_cooldown_has_exact_two_day_boundary` |
| PR-06 | Redline, failure replacement, disappearance, degraded fill, or rebuild changes a slot | Do not start or reset quality-promotion cooldown | `test_only_quality_promotion_starts_or_resets_promotion_cooldown` |
| PR-07 | A normal superior-candidate promotion occurs | Start/reset that region's two-day quality-promotion cooldown | `test_only_quality_promotion_starts_or_resets_promotion_cooldown` |

## Publication and consumer completeness

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| OUT-01 | Scheduled scan publishes normal inventory | Stable plus ranked keys equal source count and are unique | `test_no_history_maintenance_becomes_full_rebuild_and_publishes_reports` |
| OUT-02 | Sub-Store receives rejected, unavailable, unknown, and exact-ranked nodes | Return every input exactly once; only order changes | `testOperatorOrderingAndCompleteFallback`, `testDuplicateNodeAliasesAreAllPreserved` |
| OUT-03 | Sub-Store receives 250 nodes with only one known ranking key | Return all 250; known node first and unknown tail order unchanged | `testOperatorPreservesAll250InputsAndUnknownTailOrder` |
| OUT-04 | Ranking download/schema/identity validation fails | Fail open to the complete original input order | `testOperatorPreservesInputForIncompleteRankingState`, `testIdentityDriftKeepsUnknownNodes` |
| OUT-05 | Connection keys rotate while current ranking is stale | Resolve safe logical identities and keep their prior order | `testLogicalIdentityKeepsRankingAcrossConnectionRotation` |
| OUT-06 | Public ranking is served | Publish schema v2 and non-secret `identity_index`; do not expose credentials or private node results | `test_http_endpoints_and_token` |
| OUT-07 | OpenWrt/local-socks sees aliases sharing one connection | Preserve all aliases and assign distinct listeners | `testDuplicateNodeAliasesAreAllPreserved` |

## Deployment gates

Deployment is blocked unless all of the following pass:

1. Python test suite.
2. Node integration suite.
3. Python compile check, JavaScript syntax checks, and `git diff --check`.
4. On an environment with Bash, the OpenWrt apply E2E and shell-filter tests.
5. On the real Sub-Store instance, input/output node-count equality and a
   deliberate slot-order change with `noCache=true`.

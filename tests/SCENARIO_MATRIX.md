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
| ID-12 | An `other` connection rotates and its regional original name remains unique | Move the frozen-order key to the replacement connection without changing its position and force a full audit | `test_unique_name_rotation_migrates_frozen_other_order`, `test_other_connection_rotation_keeps_frozen_position_and_forces_full_audit` |

## Fixed slots, risk, and availability

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| SL-01 | Three or more safe usable nodes, no redline | Preserve healthy fixed identities | `test_maintenance_preserves_healthy_slots_and_replaces_only_failed_slot` |
| SL-02 | A fixed node becomes severe grade C and a better-grade candidate exists | Replace only that slot | `test_maintenance_quality_redline_replaces_only_one_slot` |
| SL-03 | Two fixed nodes hit redlines together | Replace only those slots with the best two dynamic candidates | `test_two_simultaneous_redlines_replace_only_their_slots_with_best_dynamic_nodes` |
| SL-04 | Redline occurs during an active quality-promotion cooldown | Risk replacement still executes immediately | `test_redline_replacement_ignores_active_quality_promotion_cooldown` |
| SL-05 | Fixed node with fewer than six healthy days is confirmed unavailable after delayed retries | Replace it that day | `test_unavailable_stable_uses_one_day_grace_only_after_six_healthy_days` |
| SL-06 | Fixed node with at least six healthy days has its first confirmed unavailable day | Preserve its slot, clear the streak, and activate one grace day | `test_maintenance_keeps_temporarily_unavailable_stable_slot` |
| SL-07 | Grace-protected node is still unavailable on the next valid day | Replace it and return it to the ordinary dynamic tail | `test_protected_stable_is_replaced_on_second_valid_unavailable_day` |
| SL-08 | Grace-protected node recovers on the next valid day | Keep its slot and restart the healthy streak at day one | `test_protected_stable_recovery_keeps_slot_and_restarts_at_day_one` |
| SL-09 | A failed node is replaced and later recovers | Give it no original-slot or special fourth/fifth-position rights | `test_replaced_node_recovers_without_original_slot_rights`, `test_unavailable_dynamic_nodes_do_not_keep_special_demotion_positions` |
| SL-10 | Every node is risky | Keep every node and compare risk before total score inside grade C | `test_all_rejected_nodes_fill_slots_by_risk_then_score`, `test_c_grade_fallback_prefers_lower_risk_before_total_score` |
| SL-11 | A/B candidates are insufficient but usable C nodes remain | Fill only affected slots with the lowest-risk usable C nodes; do not rerank the whole fixed set | `test_fallback_fills_only_affected_slots_and_keeps_rejected_nodes` |
| SL-12 | First run has no usable node | Publish no erroneous `current.json` | `test_first_rebuild_all_unavailable_aborts_without_publishing` |
| SL-13 | Node disappears from the authoritative inventory | Remove it immediately and fill the vacancy if possible | `test_missing_inventory_node_is_immediately_replaced`, `test_missing_entire_region_releases_absent_slots_in_maintenance` |
| SL-14 | Initial failure recovers during delayed retry | Keep it usable, mark transient recovery, cap the success component, and pause the streak | `test_initial_unavailable_node_retries_and_transient_recovery_pauses_streak` |
| SL-15 | Global or regional availability collapses below the configured 20%/60% threshold | Freeze slots, order, counters, grace, history, and baselines | `test_global_all_unavailable_freezes_slots_order_and_counters`, `test_availability_collapse_threshold_freezes_without_all_nodes_failing` |
| SL-16 | A prior fixed-slot map already contains an empty slot | Deep-audit every usable regional candidate before filling it | `test_existing_vacant_slot_full_audits_every_available_candidate` |
| SL-17 | Several healthy C slots have fewer fresh A/B challengers | Replace the riskiest C incumbents first and only one slot per challenger; never retain Tor while evicting a lower-risk C | `test_one_fresh_challenger_replaces_only_one_of_multiple_c_slots`, `test_fresh_challenger_replaces_the_riskiest_c_incumbent_first` |
| SL-18 | Availability protection freezes a region | Preserve trusted AI/score state and rejected membership; store current failure only as a frozen observation | `test_outage_freeze_preserves_trusted_ai_and_score_state`, `test_outage_freeze_preserves_rejected_membership_and_runtime_version` |

## Quality promotion and cooldown

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| PR-01 | Candidate has six healthy days and leads by at least 15 points on each of the latest three valid days | Promote at most one candidate | `test_default_promotion_requires_six_healthy_days_and_three_day_fifteen_point_margin` |
| PR-02 | Any of the three daily margins is insufficient | Do not promote | `test_promotion_requires_previous_day_margin_even_when_current_margin_is_large` |
| PR-03 | Same-day maintenance is run repeatedly | Do not increment the distinct-day pass count | `test_full_passes_count_distinct_calendar_days_not_same_day_reruns` |
| PR-04 | Candidate or compared stable node lacks fresh, high-confidence evidence | Do not promote | `test_promotion_waits_when_the_weakest_stable_slot_lacks_fresh_high_evidence`, `test_promotion_requires_fresh_usable_evidence_from_the_candidate` |
| PR-05 | Quality-promotion cooldown is just under or exactly seven configured-timezone calendar days | Block just under seven days; allow at the exact local-day boundary | `test_quality_promotion_cooldown_has_exact_seven_day_boundary`, `test_quality_promotion_cooldown_uses_configured_local_calendar_day` |
| PR-06 | Redline, failure replacement, disappearance, degraded fill, or rebuild changes a slot | Do not start or reset quality-promotion cooldown | `test_only_quality_promotion_starts_or_resets_promotion_cooldown` |
| PR-07 | A normal superior-candidate promotion occurs | Start/reset that region's seven-day quality-promotion cooldown | `test_only_quality_promotion_starts_or_resets_promotion_cooldown` |
| PR-08 | A required vacancy/failure replacement occurred first in the region | Skip ordinary promotion in that run | `test_vacant_slot_fill_blocks_same_run_promotion_after_cooldown` |

## Quality, Claude, and audit coverage

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| QA-01 | A higher-score/lower-latency B node competes with an A node | Grade A ranks first | `test_grade_precedes_score_and_latency_in_ranking` |
| QA-02 | Residential evidence is confirmed, probable, auxiliary-only, or conflicts with Hosting | Award 10, 5, or 0 points according to the evidence rules | `test_residential_evidence_levels` |
| QA-03 | Risk coverage is insufficient, Tor/DNSBL/high-risk consensus is severe, or crawler is the only signal | Cap insufficient evidence, grade confirmed severe evidence C, and treat crawler as a small penalty only | `test_unknown_risk_values_do_not_count_as_coverage_or_full_score`, `test_dnsbl_requires_multiple_listings_for_a_confirmed_redline`, `test_three_source_proxy_consensus_is_risk_c`, `test_crawler_only_is_a_small_penalty_but_not_a_risk_downgrade` |
| QA-04 | Claude uses a dedicated egress | Keep trace country authoritative for service support, record provider country separately, score routes independently, and pause quality evidence when the two country sources conflict | `test_claude_split_route_collects_two_source_risk_intelligence`, `test_claude_trace_country_is_not_overwritten_by_risk_provider_country`, `test_claude_route_evidence_does_not_fill_generic_risk_coverage`, `test_high_risk_and_factor_consensus_do_not_cross_egress_routes`, `test_two_high_risk_sources_on_claude_route_are_risk_c`, `test_claude_country_conflict_pauses_quality_evidence` |
| QA-05 | Claude is supported, restricted, partially reachable, unreachable, rate-limited, or times out | Produce `available`, `restricted`, `degraded`, `unreachable`, or `unknown` deterministically and reject HTTP errors as successful reachability | `test_claude_status_classification`, `test_quick_http_get_rejects_http_error_responses` |
| QA-06 | At least five distinct supported service egresses exist and 80% fail or degrade on the same AI service | Deduplicate aliases by ChatGPT/Claude egress, reject a zero threshold, retain trusted AI evidence, and use same-egress historical country only when current country is missing | `test_ai_service_outage_preserves_previous_ai_grade_and_blocks_history_growth`, `test_ai_service_outage_guard_requires_minimum_sample`, `test_ai_service_outage_guard_deduplicates_shared_service_egresses`, `test_ai_outage_country_fallback_requires_same_exit_ip`, `test_chatgpt_outage_denominator_excludes_unsupported_exit_countries`, `test_claude_degraded_fleet_triggers_service_outage_guard`, `test_ai_service_failure_ratio_must_be_positive` |
| QA-07 | Stable slots and top challengers need daily evidence while the remainder rotates | Audit all fixed slots plus three challengers daily, force any Claude-route change including empty-to-known, and cover the rest within two days at the default 50% rate | `test_default_audit_plan_checks_three_challengers_daily_and_covers_pool_in_two_days`, `test_newly_observed_claude_route_forces_a_full_audit` |
| QA-08 | A prior risk result conflicts across sources | Force a fresh full audit outside the normal rotation | `test_risk_conflict_forces_full_audit_outside_rotation` |
| QA-09 | A pre-upgrade schema-v2 state lacks all new fields | Preserve slots and initialize the new state incrementally | `test_legacy_v2_state_keeps_slots_and_initializes_new_history_incrementally` |
| QA-10 | A temporary subscription audit sees a transient node failure or fleet-wide AI failure | Reuse delayed quick retries and the distinct-egress AI outage guard without changing production ranking state | `test_subscription_audit_retries_transient_quick_failure`, `test_subscription_audit_applies_ai_service_outage_guard` |
| QA-11 | A split Claude route has no current country | Reuse only the country from the same historical Claude egress; never borrow a different generic egress country | `test_claude_outage_country_fallback_is_scoped_to_claude_egress` |

## Frozen `other` ordering

| ID | Scenario | Required result | Automated coverage |
|---|---|---|---|
| OT-01 | `rebuild` contains `other` nodes | Full-quality ordering replaces the previous frozen baseline; no stable 1-3 slots are created | `test_other_rebuild_ranks_quality_then_maintenance_freezes_and_appends`, `test_other_next_rebuild_replaces_the_frozen_order` |
| OT-02 | Scores, risk, latency, or reachability change during `maintenance` | Update health metadata but preserve the frozen `other` order | `test_other_rebuild_ranks_quality_then_maintenance_freezes_and_appends`, `test_other_order_is_frozen_during_maintenance_and_rebuilt_on_demand` |
| OT-03 | A new `other` node appears during `maintenance` | Append it after every surviving frozen identity in inventory order | `test_other_rebuild_ranks_quality_then_maintenance_freezes_and_appends` |
| OT-04 | An `other` node disappears during `maintenance` | Remove it and preserve the relative order of every survivor | `test_other_maintenance_removes_deleted_nodes_without_reordering_survivors` |
| OT-05 | The deployed state predates frozen `other` ordering | Seed the baseline from the active `current.json` and continue maintenance without an automatic rebuild | `test_state_without_frozen_order_inherits_current_other_without_rebuild` |

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
| OUT-08 | Reports disable exit-IP output | Remove generic, Claude, full-audit, evidence, regional-status, and free-form error-string IPs from JSON and Markdown | `test_report_exit_ip_redaction_covers_nested_claude_full_and_region_fields`, `test_exit_ip_redaction_removes_literals_embedded_in_error_strings` |
| OUT-09 | Only a rejected-node reason string changes | Keep the runtime version stable; change it only when rejected membership or actual ordering changes | `test_runtime_version_ignores_rejected_reason_text_but_tracks_membership` |
| OUT-10 | A report contains Claude-route risk or country-conflict reasons | Render Chinese labels instead of exposing internal reason codes | `test_claude_risk_reasons_have_chinese_report_labels` |
| OUT-11 | Runtime order is unchanged across scans or current commit fails | Give every scan a unique state revision/archive and let old current select only its committed snapshot | `test_same_runtime_version_failed_commit_cannot_advance_state`, `test_each_scheduled_run_has_an_immutable_versioned_archive` |

## Deployment gates

Deployment is blocked unless all of the following pass:

1. Python test suite.
2. Node integration suite.
3. Python compile check, JavaScript syntax checks, and `git diff --check`.
4. On an environment with Bash, the OpenWrt apply E2E and shell-filter tests.
5. On the real Sub-Store instance, input/output node-count equality and a
   deliberate slot-order change with `noCache=true`.

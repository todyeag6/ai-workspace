# Traceability Matrix — Aiwebscapes Platform

This matrix maps each shipped requirement to the code that satisfies it and the
test that proves it. It is the release-gate item "traceability matrix complete".
Phase 1/2 rows are carried forward from earlier sessions; Phase 3/4/5 rows were
added in this reconciliation. The file is a requirement→implementation map, **not
a status report** — for current build state, run:

```bash
bash scripts/status.sh
```

If this markdown and `scripts/status.sh` disagree, the script is right (per
`docs/HANDOFF.md` ground rules). `git log` is the task record: every `feat`
commit subject already carries its requirement IDs, so this file references them
rather than re-counting.

---

## Phase 1 & 2 (carried forward)

Phase 1 and Phase 2 rows were authored in prior sessions and are reproduced here
for completeness; the authoritative verification is `tests/` + `scripts/status.sh`.

| Phase | Requirement | Where satisfied | Verified by |
|---|---|---|---|
| P1 | FR-DASH-001/002, LFR-DASH-*, A11Y-001..006, AC-001 | `src/Dashboard/*`, `tests/Dashboard/*` | `tests/Dashboard/PipelineTest`, `tests/Dashboard/AccessibilityTest` |
| P2 | FR-AGENT-003 (eval-gated activation) | `src/Eval/*`, `src/Agents/AgentRegistry` | `tests/Eval/EvalHarnessTest`, `AgentRegistryTest::test_evaluation_*` |
| P2 | FR-TOOL-003, FR-AI-001 cost routing | `src/AI/ModelRouter`, `src/Connectors/*` | `ModelRouterCostTest`, `ConnectorExecutorTest` |
| P2 | FR-ORCH-003, BRD Table 4/6 reporting | `src/Workflow/WorkflowBuilder`, `src/Reporting/ReportAssembler` | `WorkflowBuilderTest`, `ReportAssemblerTest` |
| P2 | BR-9.1/11.1/12.6 managed-ops substrate | `src/ManagedOps/*` | `AgentOwnershipTest`, `SlaRecordTest`, `SupportModelTest` |
| P2 | P2-T5 packaged vertical offering | `src/VerticalOffering/*` | `tests/VerticalOffering/VerticalOfferingTest` |

> Note: the historical commit `d81a7b4 docs: fix stale TRACEABILITY.md status (Option A)`
> previously patched only the Phase-1 header; this rewrite supersedes it and
> extends coverage through Phase 5.

---

## Phase 3 — Defensive Security Agent (FRD §2, SFR-*/SBR-*)

All P3 tasks are committed and pushed (`git log` `01c7c91`..`58844d4`). Policies
`AI_TRIAGE_POLICY`, `REMEDIATION_POLICY`, `REPORT_POLICY`, `FINDING_SLA`,
`SCANNER_ISOLATION_POLICY`, `SCANNER_TARGET_POLICY`, `SCAN_SCHEDULE_POLICY`,
`NFR_SLA_POLICY` are RATIFIED (owner, 2026-08-10/12). `SCANNER_ISOLATION_POLICY`
and `SCANNER_TARGET_POLICY` headers still read PROPOSED but their pinning tests
assert RATIFIED values — ratify-on-pin discipline; the values are locked either way.

| Requirement | Where satisfied | Verified by |
|---|---|---|
| SFR-AUTH-001/002/003, SBR-3.1/3.2 (authorization & scope) | `src/SecurityAgent/Authorization.php`, `OwnershipVerifier.php` | `tests/SecurityAgent/AuthorizationScopeTest::test_ownership_proof_required_before_active`, `::test_out_of_scope_request_rejected_and_recorded` |
| SFR-SAFE-001/002/003, SBR-3.3/3.5 (safety monitor + kill switch) | `src/SecurityAgent/SafetyMonitor.php`, `KillSwitch.php` | `tests/SecurityAgent/SafetyMonitorTest`, `ScanSchedulerTest::test_cannot_schedule_without_complete_authorization` |
| SFR-ASSET-001, SFR-SCAN-001/002/003 (asset inventory + sandboxed scanners) | `src/SecurityAgent/Asset.php`, `SafeScannerInvoker.php`, `SanitizedTarget.php` | `tests/SecurityAgent/AssetAndScannerTest`, `ScannerIsolationTest::test_scanner_adapter_disabled_when_untrusted`, `ScannerTargetSafetyTest` |
| SFR-EVID-001/002, SFR-FIND-002, SFR-SELF-004 (evidence + redaction) | `src/SecurityAgent/EvidenceProcessor.php`, `RedactionScanner.php` | `tests/SecurityAgent/EvidenceProcessorTest::test_processor_refuses_unredacted_sensitive_evidence`, `::test_redaction_is_allowlist_driven_not_pattern_hunt` |
| SFR-FIND-001/002, SFR-AI-001 (finding engine + occurrence history) | `src/SecurityAgent/FindingEngine.php`, `FindingOccurrence.php` | `tests/SecurityAgent/FindingEngineTest::test_repeated_evidence_appends_occurrence_without_destroying_state`, `::test_the_same_issue_in_two_tenants_is_two_findings` |
| P3-T6 (AI triage, non-authoritative) | `src/SecurityAgent/TriageAssistant.php`, `AI_TRIAGE_POLICY.php` | `tests/SecurityAgent/TriageAssistantTest::test_attaching_a_suggestion_cannot_alter_the_human_decision`, `::test_the_triage_path_has_no_method_that_closes_a_finding` |
| P3-T7 (remediation tracker, evidenced closure) | `src/SecurityAgent/RemediationTracker.php`, `Retest.php` | `tests/SecurityAgent/RemediationTrackerTest::test_closure_succeeds_on_a_passing_retest_with_evidence_linked_to_remediation`, `::test_a_failing_retest_walks_a_claimed_fix_back_to_in_progress` |
| P3-T8 (reporting, refusing redaction gate) | `src/SecurityAgent/ReportExporter.php`, `ReportRedactionRequired.php` | `tests/SecurityAgent/SecurityReportingTest::test_a_secret_reaching_a_report_refuses_the_report`, `::test_a_session_token_reaching_a_report_refuses_the_report`, `::test_a_foreign_tenants_finding_refuses_the_report`, `::test_exporting_a_report_writes_an_audit_row`, `::test_the_audit_row_records_a_digest_not_the_report_body` |
| NFR Table 5 (service levels / perf budgets) | `config/security/NFR_SLA_POLICY.php` (RATIFIED) | `tests/SecurityAgent/NfrSlaPolicyTest::test_shipped_nfr_sla_policy_pins_its_contract_terms` |

---

## Phase 4 — Deployment, Managed-Ops, Hardware Sizing (BRD §16 Phase 4, BR-9.1/9.2)

All P4 tasks committed and pushed (`4b7803d`..`4a23a47`). `HARDWARE_SIZING` and
`REMOTE_SUPPORT_POLICY` are RATIFIED 2026-08-12.

| Requirement | Where satisfied | Verified by |
|---|---|---|
| BRD Phase4 #1, BR-9.2 (hardware sizing profiles) | `src/Deploy/HardwareSizing.php`, `config/deploy/HARDWARE_SIZING.php` (RATIFIED) | `tests/Deploy/HardwareSizingTest::test_policy_is_ratified_by_owner`, `HardwareSizingSelectorTest::test_recommend_returns_largest_fitting_tier` |
| BR-9.1/FR-DATA-001 (fail-closed client deploy validator) | `src/Deploy/DeployClientValidator.php` | `tests/Deploy/DeployClientValidatorTest::test_local_deploy_with_cloud_db_dsn_refused`, `::test_hybrid_deploy_may_use_cloud_db_dsn` |
| AC-006, SFR-SELF-003 (hybrid local inference, in-stack Ollama) | `src/Deploy/LocalInferenceProfile.php` | `tests/Deploy/LocalInferenceProfileTest::test_restricted_data_class_refuses_cloud_egress`, `::test_hybrid_prefers_local_ollama_url` |
| FR-DATA-001, AC-006 (local vector/data services, fail-closed) | `src/Deploy/LocalDataServices.php` | `tests/Deploy/LocalDataServicesValidatorTest::test_local_with_cloud_db_dsn_refused`, `LocalDataServicesComposeTest` |
| SEC-005 (opt-in remote-support telemetry, deny-by-default) | `src/Deploy/RemoteSupport.php`, `config/deploy/REMOTE_SUPPORT_POLICY.php` (RATIFIED) | `tests/Deploy/RemoteSupportTest::test_telemetry_refused_when_policy_disabled`, `::test_telemetry_payload_carries_no_client_data` |
| BR-9.1/BR-9.2 (client-admin runbooks, cert checklist, STRIDE) | `docs/client-admin/*`, `docs/THREAT_MODEL.md` | `tests/Deploy/ClientAdminRunbooksTest`, `ClientAdminThreatModelTest` (keyword coverage) |

---

## Phase 5 — Industry Templates, Compliance, Multi-Region (BRD §16 Phase 5 #2/#4/#5)

P5-T1/T2 (partner program + mature service management) are **OUT-OF-REPO docs
only** — see `docs/partner-program/README.md`, `docs/service-management/README.md`.
P5-T3/T4/T5-T8/T9 are in-repo with tests. `REGION_TOPOLOGY.php` is PROPOSED and
default-off (see open-call note below).

| Requirement | Where satisfied | Verified by |
|---|---|---|
| BRD §16 #2 (industry template presets + instantiation) | `src/Deploy/IndustryTemplate.php`, `src/Deploy/DeployClientValidator.php` | `tests/Deploy/IndustryTemplateTest::test_legal_template_binds_small_profile_with_data_residency`, `TemplateInstantiationTest` |
| BRD §16 #4 (control-mapping engine + NIST CSF 2.0 / ISO 27001:2022 / SOC 2 TSC) | `src/Compliance/ControlMapping.php`, `ReadinessReport.php`, `config/compliance/{NIST_CSF_2_0,ISO_27001_2022,SOC2_TSC}.php` | `tests/Compliance/ControlMappingTest::test_known_frameworks_are_the_verified_official_set`, `NistCsfMappingTest::test_mapping_uses_real_csf_2_0_functions`, `IsoSoc2MappingTest::test_iso_version_pinned_and_maps_to_annex_a`, `::test_soc2_version_pinned_and_maps_to_tsc`, `ReadinessReportTest::test_unmapped_mandatory_control_is_flagged_not_omitted` |
| BRD §16 #5 (region topology + residency validator, default-off) | `src/Deploy/MultiRegionTopology.php`, `config/deploy/REGION_TOPOLOGY.php` (PROPOSED) | `tests/Deploy/MultiRegionTopologyTest::test_default_is_single_region_and_disabled`, `::test_enabled_without_justification_refused`, `::test_region_outside_allowlist_refused`, `::test_local_model_never_replicates_even_if_justified` |

---

## Phase 5 — Open calls (not yet closed)

These are explicitly **not** silently "done". They are deferred decisions the
owner must make; the engine already enforces the safe posture.

- **`REGION_TOPOLOGY.php` is PROPOSED + default-off.** Multi-region replication is
  deny-by-default (SEC-005). `MultiRegionTopology` refuses enablement without
  `justified: true`, refuses any region outside `residency_allowlist`, and never
  replicates a `local` deployment model. Before any multi-region use the owner
  must: (1) flip STATUS to RATIFIED, (2) populate `residency_allowlist` with the
  specific approved regions, (3) record the data-residency justification. The
  cells above prove the guardrails; they do **not** constitute sign-off.
- **Compliance framework selection (which PCI/HIPAA regimes) is deferred.** The
  `ControlMapping` engine is generic — `test_known_frameworks_are_the_verified_official_set`
  pins exactly the three shipped frameworks (NIST CSF 2.0 Feb 2024, ISO/IEC
  27001:2022, SOC 2 TSC 2017 + 2022 PoF). PCI-DSS / HIPAA mappings are not
  present; adding them is a new task sourcing the newest official revision, not a
  hidden gap. `test_unknown_framework_refused` keeps the engine closed to
  unverified frameworks.

---

## Phase-1 Exit Gate (plan §995) — status

**This file is a requirement→implementation map, not a status report.** The
"green / how many tests" numbers are intentionally NOT maintained here — prose
status rots the moment a commit lands. For current build state, run the
ground-truth script:

```bash
bash scripts/status.sh
```

That prints branch, HEAD, clean-tree, unpushed-commit count, the full delivered
task list (from `git log` commit subjects, which already carry the requirement
IDs), and the verify commands — all derived from git at run time. If this
markdown and `scripts/status.sh` disagree, the script is right.

- [ ] Pen-test window (SEC-009 / SFR-AUTH-001) — OPEN, book before release.
- [ ] `REGION_TOPOLOGY.php` owner ratification + `residency_allowlist` population — OPEN (PROPOSED, default-off).
- [ ] SEC-008 branch protection — BLOCKED by GitHub Free tier; documented OPEN, not skipped.

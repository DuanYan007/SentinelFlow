# Phase 1 Formal Plan

## 1. Scope

Phase 1 focuses on validating the full end-to-end workflow for ransomware detection.

Primary goal:
- verify Agent-driven orchestration
- verify full-path traceability
- produce stable three-class results

Phase-1 workflow:
- `sample -> hash intelligence -> Agent -> static analysis -> dynamic analysis -> verdict -> JSON`

Phase-1 constraints:
- no early termination shortcuts
- prioritize full workflow coverage
- keep the implementation minimal and reproducible

## 2. JSON Schema

Top-level structure:

```json
{
  "sample": {},
  "threat_intel": {},
  "agent_trace": [],
  "static_analysis": {},
  "dynamic_analysis": {},
  "verdict": {},
  "runtime": {}
}
```

### 2.1 `sample`

| Field | Type | Description |
|---|---|---|
| `file_name` | string | Sample filename |
| `file_path` | string | Absolute or project-relative path |
| `file_size` | integer | File size in bytes |
| `file_type` | string | File type, such as `PE32 executable` |
| `md5` | string | MD5 hash |
| `sha1` | string | SHA1 hash |
| `sha256` | string | SHA256 hash |
| `submitted_at` | datetime | Analysis start time |

### 2.2 `threat_intel`

| Field | Type | Description |
|---|---|---|
| `source` | string | Intelligence source, initially `virustotal` |
| `query_hash_type` | string | Hash type used for lookup |
| `query_hash_value` | string | Queried hash value |
| `matched` | boolean | Whether an intelligence hit exists |
| `malicious_count` | integer | Number of malicious detections |
| `suspicious_count` | integer | Number of suspicious detections |
| `harmless_count` | integer | Number of harmless detections |
| `undetected_count` | integer | Number of undetected engines |
| `reputation` | integer | VT reputation if available |
| `label` | string | Threat label if available |
| `permalink` | string | VT result URL |
| `raw_summary` | string | Short normalized summary |
| `status` | string | `ok` or `error` |
| `error` | string/null | Error message if query failed |

### 2.3 `agent_trace`

Each item is an event object.

| Field | Type | Description |
|---|---|---|
| `step_id` | integer | Step number in current workflow |
| `stage` | string | Current phase name |
| `decision` | string | Agent decision |
| `reason` | string | Natural-language rationale |
| `input_summary` | object | Compact evidence summary |
| `used_skill` | string | Skill used, if any |
| `used_tool` | string | Tool used, if any |
| `confidence` | number | Decision confidence in `[0,1]` |
| `timestamp` | datetime | Event time |

Recommended `stage` values:
- `sample_ingest`
- `hash_intel`
- `agent_decision_1`
- `static_analysis`
- `agent_decision_2`
- `dynamic_analysis`
- `final_verdict`

### 2.4 `static_analysis`

| Field | Type | Description |
|---|---|---|
| `executed` | boolean | Whether static analysis ran |
| `tools_used` | string[] | Static tools invoked |
| `pe_features` | object | PE structure features |
| `import_features` | object | Import-table features |
| `string_features` | object | Extracted string-based features |
| `matched_features` | string[] | Normalized matched indicators |
| `risk_score` | number | Static risk score in `[0,1]` |
| `score_breakdown` | object[] | Feature-level score contributions |
| `summary` | string | Short static summary |
| `status` | string | `ok`, `partial`, or `error` |
| `error` | string/null | Error message if failure occurred |

`pe_features`:
- `section_count`
- `high_entropy_sections`
- `packed_or_obfuscated`
- `suspicious_timestamp`
- `entrypoint_anomaly`

`import_features`:
- `crypto_api_count`
- `filesystem_api_count`
- `process_api_count`
- `registry_api_count`
- `shadowcopy_or_recovery_api_present`

`string_features`:
- `ransom_note_keywords`
- `extension_change_keywords`
- `cmd_keywords`
- `url_or_onion_indicators`
- `config_like_strings`

### 2.5 `dynamic_analysis`

| Field | Type | Description |
|---|---|---|
| `executed` | boolean | Whether dynamic analysis ran |
| `environment` | string | Dynamic environment name |
| `tools_used` | string[] | Dynamic tools invoked |
| `execution_status` | string | `success`, `partial`, `failed_to_execute`, or `timed_out` |
| `process_events` | object[] | Process-level events |
| `file_events` | object[] | File-level events |
| `matched_features` | string[] | Normalized matched indicators |
| `risk_score` | number | Dynamic risk score in `[0,1]` |
| `score_breakdown` | object[] | Feature-level score contributions |
| `summary` | string | Short dynamic summary |
| `status` | string | `ok`, `partial`, or `error` |
| `error` | string/null | Error message if failure occurred |

`process_events` fields:
- `process_name`
- `parent_process`
- `child_process_count`
- `command_line`
- `suspicious_spawn`

`file_events` fields:
- `created_count`
- `modified_count`
- `renamed_count`
- `deleted_count`
- `high_frequency_write`
- `target_extensions`

### 2.6 `verdict`

| Field | Type | Description |
|---|---|---|
| `final_label` | string | `malicious`, `suspicious`, or `benign` |
| `final_score` | number | Final score in `[0,1]` |
| `decision_basis` | string[] | Human-readable supporting evidence |
| `explanation` | string | Final explanation |

### 2.7 `runtime`

| Field | Type | Description |
|---|---|---|
| `workflow_id` | string | Workflow identifier |
| `start_time` | datetime | Start time |
| `end_time` | datetime | End time |
| `duration_sec` | number | Runtime duration |
| `phase` | string | Current project phase |
| `notes` | string | Additional notes |

## 3. Agent Decision Rules

Phase-1 default path:

```text
hash_intel -> static_analysis -> dynamic_analysis -> final_verdict
```

### 3.1 After Hash Intelligence

| Condition | Decision | Rationale |
|---|---|---|
| VT clearly malicious | `continue_to_static` | Phase 1 still needs full-path validation |
| VT not found | `continue_to_static` | Static is the default next step |
| VT information insufficient | `continue_to_static` | Fill evidence gap with static analysis |
| VT query failed | `continue_to_static` | Keep workflow moving and record the error |

### 3.2 After Static Analysis

| Condition | Decision | Rationale |
|---|---|---|
| `static_score >= 0.60` | `continue_to_dynamic` | Dynamic evidence is still required |
| `0.30 <= static_score < 0.60` | `continue_to_dynamic` | Add dynamic evidence |
| `static_score < 0.30` | `continue_to_dynamic` | Phase 1 still validates dynamic branch |
| Static module error | `continue_to_dynamic` | Preserve coverage and keep error in output |

### 3.3 After Dynamic Analysis

| Condition | Decision | Rationale |
|---|---|---|
| `dynamic_score >= 0.60` | `produce_final_verdict` | Evidence is sufficient for phase-1 output |
| `0.30 <= dynamic_score < 0.60` | `produce_final_verdict` | Combine with other evidence |
| `dynamic_score < 0.30` | `produce_final_verdict` | Still must emit a final label |
| Dynamic module error | `produce_final_verdict` | Use existing evidence and record failure |

### 3.4 Final Verdict Mapping

| Condition | Output |
|---|---|
| High-confidence VT malicious and at least one other source supports it | `malicious` |
| Static high and dynamic medium-or-high | `malicious` |
| Partial abnormal evidence but insufficient certainty | `suspicious` |
| VT non-malicious, static low, dynamic low | `benign` |

## 4. Minimum Viable Tool Candidates

### 4.1 Threat Intelligence

Recommended:
- `VirusTotal API`

Reason:
- aligns with the chosen phase-1 entrance
- low integration complexity
- provides useful baseline labels and engine counts

### 4.2 Static Analysis

Recommended minimum set:
- `pefile`
- `strings`
- `Detect It Easy (DIE)`

Responsibilities:
- `pefile`: PE structure, sections, imports
- `strings`: ransom-note text, extension names, command traces, config-like text
- `DIE`: packer, obfuscation, compiler/packer fingerprints

Not required in phase 1:
- disassembly-heavy pipelines
- control-flow recovery
- deobfuscation frameworks

### 4.3 Dynamic Analysis

Recommended minimum direction:
- `Windows VM`
- existing behavior collection tool or lightweight sandbox

Required environment properties:
- snapshot rollback support
- real PE execution capability
- process and file event export
- repeatable runs

Implementation preference:
- prefer existing tools first
- avoid self-building a full sandbox in phase 1

### 4.4 Recommended Phase-1 Tool Stack

- Threat intelligence: `VirusTotal API`
- Static analysis: `pefile + strings + DIE`
- Dynamic analysis: `Windows VM + existing behavior collection tool`
- Orchestration stack: to be confirmed before implementation

## 5. Error Handling And Exceptional Branches

Phase 1 should be resilient. Module failure should not collapse the whole record.

### 5.1 Global Rules

- Every module writes `status` and `error`
- Errors are recorded into final JSON
- Agent continues whenever the next stage can still provide value
- Only unrecoverable input errors may stop the workflow entirely

### 5.2 Input Errors

| Error | Handling |
|---|---|
| File not found | Stop workflow and emit minimal JSON with failure status |
| File unreadable | Stop workflow and emit minimal JSON with failure status |
| Non-PE sample in a PE-only phase-1 run | Mark as unsupported input and emit minimal JSON |

### 5.3 Threat-Intel Errors

| Error | Handling |
|---|---|
| VT timeout | Record error and continue to static |
| VT API quota exceeded | Record error and continue to static |
| VT network failure | Record error and continue to static |
| VT schema mismatch | Record error and normalize as `status=error` |

### 5.4 Static-Analysis Errors

| Error | Handling |
|---|---|
| `pefile` parse failure | Record `status=error`, continue to dynamic |
| `strings` extraction failure | Record `status=partial`, continue to dynamic |
| DIE unavailable | Record `status=partial`, continue to dynamic |
| One tool succeeds and another fails | Preserve partial features and continue |

### 5.5 Dynamic-Analysis Errors

| Error | Handling |
|---|---|
| VM boot failure | Record `status=error`, continue to final verdict |
| Sample fails to execute | Record `execution_status=failed_to_execute`, continue to verdict |
| Event collection incomplete | Record `status=partial`, continue to verdict |
| Execution timeout | Record `execution_status=timed_out`, continue to verdict |

### 5.6 Verdict Fallback Rules

- If VT succeeds but static and dynamic both fail:
  - produce `suspicious` or `malicious` based on VT strength
- If VT fails, static succeeds, dynamic fails:
  - use static-led verdict
- If VT fails, static fails, dynamic succeeds:
  - use dynamic-led verdict
- If all evidence modules fail:
  - emit `suspicious`
  - explanation must state evidence collection failure

## 6. Threshold Draft

These thresholds are phase-1 operational defaults, not final research conclusions.

### 6.1 VT Signal Threshold

Suggested signal mapping:

| Condition | Signal |
|---|---|
| `malicious_count >= 10` | `high` |
| `3 <= malicious_count < 10` | `medium` |
| `0 <= malicious_count < 3` | `low` |

Notes:
- this is only a workflow-support threshold
- phase 1 still does not early-terminate on VT

### 6.2 Static Score Threshold

| Score Range | Signal |
|---|---|
| `0.60 - 1.00` | `high` |
| `0.30 - 0.59` | `medium` |
| `0.00 - 0.29` | `low` |

Suggested phase-1 weighting:
- `risk_score = 0.3 * pe_score + 0.3 * import_score + 0.4 * string_score`

High-weight static features:
- ransom-note keywords
- backup deletion or recovery-disabling commands
- strong crypto-related imports

Medium-weight static features:
- packer or obfuscation signs
- multiple high-entropy sections

Low-weight static features:
- suspicious timestamp only

### 6.3 Dynamic Score Threshold

| Score Range | Signal |
|---|---|
| `0.60 - 1.00` | `high` |
| `0.30 - 0.59` | `medium` |
| `0.00 - 0.29` | `low` |

Suggested phase-1 weighting:
- `risk_score = 0.4 * process_score + 0.6 * file_score`

High-weight dynamic features:
- bulk file rename
- high-frequency write activity

Medium-weight dynamic features:
- suspicious child process spawn
- repeated modification behavior

Low-weight dynamic features:
- execution success without clear malicious behavior

### 6.4 Phase-1 Final Verdict Threshold Draft

Phase 1 should prefer simple and stable verdict rules.

Suggested operational mapping:

| Evidence Pattern | Suggested Label |
|---|---|
| `vt_signal=high` and (`static_signal>=medium` or `dynamic_signal>=medium`) | `malicious` |
| `dynamic_signal=high` | `malicious` |
| `static_signal=high` and `dynamic_signal>=medium` | `malicious` |
| one medium signal only, or mixed weak abnormal evidence | `suspicious` |
| all signals low | `benign` |
| evidence collection failure in 2 or more major modules | `suspicious` |

Suggested phase-1 final score:
- `final_score = 0.3 * vt_score + 0.3 * static_score + 0.4 * dynamic_score`

Notes:
- this score is for consistent output only
- it is not yet intended as the final research scoring method

## 6A. Error Handling Refinement

### 6A.1 Failure Severity

Suggested severity levels:

| Severity | Meaning | Action |
|---|---|---|
| `fatal` | Workflow cannot continue meaningfully | stop and emit minimal JSON |
| `recoverable` | Current module fails but later modules can still provide value | continue and record error |
| `partial` | Module returns incomplete evidence | continue and mark partial |

Recommended mapping:
- file missing: `fatal`
- file unreadable: `fatal`
- VT timeout/quota/network failure: `recoverable`
- one static tool failure: `partial`
- VM boot failure: `recoverable`
- dynamic execution timeout: `partial`

### 6A.2 Standard Error Object

Every module should normalize errors into:

```json
{
  "status": "error",
  "error": {
    "code": "VT_TIMEOUT",
    "message": "VirusTotal query timed out",
    "severity": "recoverable"
  }
}
```

Recommended error fields:
- `code`
- `message`
- `severity`

### 6A.3 Fallback Matrix

| VT | Static | Dynamic | Recommended Handling | Suggested Label Bias |
|---|---|---|---|---|
| ok | ok | ok | normal verdict | evidence-driven |
| error | ok | ok | static+dynamic verdict | no VT dependence |
| ok | error | ok | VT+dynamic verdict | slightly malicious-biased if VT high |
| ok | ok | error | VT+static verdict | slightly malicious-biased if static high |
| error | error | ok | dynamic-led verdict | cautious |
| error | ok | error | static-led verdict | cautious |
| ok | error | error | VT-led verdict | cautious |
| error | error | error | emit degraded result | `suspicious` |

### 6A.4 Trace Requirements For Failures

When an error happens:
- add one `agent_trace` item for the failure
- add one `agent_trace` item for the recovery decision if workflow continues
- keep failure reasons short and explicit

Suggested failure decisions:
- `continue_after_vt_error`
- `continue_after_static_error`
- `continue_after_dynamic_error`
- `emit_degraded_verdict`

## 6B. Dynamic Environment Requirements

### 6B.1 Minimum Environment Requirements

Phase-1 dynamic environment should satisfy all of the following:
- Windows-based execution target
- snapshot and rollback support
- isolated networking policy or controllable network mode
- ability to copy in one sample at a time
- ability to export basic process and file events
- repeatable execution procedure

### 6B.2 Recommended Operational Properties

Preferred but not strictly mandatory in phase 1:
- clean baseline image
- no unnecessary background software
- fixed observation window
- easy reset between runs
- separate result export directory

### 6B.3 Observation Window Draft

Suggested initial observation window:
- startup and execution preparation: `0-10s`
- main behavior collection: `10-60s`
- optional tail window: `60-90s`

Phase-1 recommendation:
- default total window: `60s`

Rationale:
- enough to observe basic process and file behavior
- short enough for repeated batch experiments later

### 6B.4 Network Policy Draft

Suggested phase-1 options:

| Policy | Use |
|---|---|
| `host-only / isolated` | safest default |
| `restricted outbound with monitoring` | use only if behavior depends on network |

Phase-1 recommendation:
- start with isolated or host-only mode
- only relax if execution evidence shows the sample requires network interaction

### 6B.5 Minimum Dynamic Evidence Set

Phase-1 should at minimum export:
- process start event
- parent-child process relation
- file create count
- file modify count
- file rename count
- execution status
- observation duration

### 6B.6 Run Hygiene

Suggested run hygiene rules:
- one sample per VM run
- rollback after every run
- separate result folder per sample
- never reuse a dirty VM state for a new sample

## 7. Suggested Phase-1 Delivery Order

1. finalize JSON schema
2. integrate VT lookup
3. integrate `pefile + strings + DIE`
4. prepare Windows VM dynamic environment
5. implement full workflow orchestration
6. run one VT-confirmed malicious sample
7. expand to a small batch
8. add a small benign set

## 8. VT Result Normalization Rules

The threat-intelligence module should normalize VT responses into a stable internal structure.

### 8.1 Normalized Output Goals

- hide raw API schema differences from downstream modules
- expose only the fields required by phase 1
- keep error conditions explicit

### 8.2 Normalized VT Fields

Recommended normalized fields:
- `source`
- `query_hash_type`
- `query_hash_value`
- `matched`
- `malicious_count`
- `suspicious_count`
- `harmless_count`
- `undetected_count`
- `reputation`
- `label`
- `permalink`
- `raw_summary`
- `status`
- `error`

### 8.3 Hash Lookup Outcomes

| Raw Situation | Normalized `matched` | Normalized `status` | Notes |
|---|---|---|---|
| exact hash result found | `true` | `ok` | normal case |
| hash not found | `false` | `ok` | no hit is not an error |
| request timeout | `false` | `error` | continue workflow |
| quota exceeded | `false` | `error` | continue workflow |
| schema parse failure | `false` | `error` | keep raw message in `error` |

### 8.4 VT Signal Normalization

Suggested normalized VT signal:

| Condition | `vt_signal` |
|---|---|
| `malicious_count >= 10` | `high` |
| `3 <= malicious_count < 10` | `medium` |
| `0 <= malicious_count < 3` | `low` |

If `status=error`:
- set `vt_signal = unknown`

### 8.5 Label Normalization

Do not depend on raw vendor-specific family names in phase 1.

Suggested normalized `label` values:
- `ransomware`
- `malware`
- `unknown`

Mapping guidance:
- if VT label or summary clearly indicates ransomware, normalize to `ransomware`
- if VT only indicates generic malware, normalize to `malware`
- otherwise normalize to `unknown`

### 8.6 Raw Summary Normalization

`raw_summary` should be compact and human-readable.

Recommended pattern:
- `VT hit with high malicious count`
- `VT no hit`
- `VT query failed: timeout`

## 9. Static Feature Naming And Normalization Rules

The static-analysis module should emit stable feature names independent of the underlying tool.

### 9.1 Naming Principles

- use lowercase snake_case
- use semantic names, not tool-specific names
- one feature name should represent one analytic meaning

### 9.2 Normalized Static Feature Names

Recommended phase-1 normalized names:
- `packed_binary`
- `high_entropy_sections`
- `suspicious_timestamp`
- `entrypoint_anomaly`
- `imports_crypto_api`
- `imports_shadowcopy_or_recovery_api`
- `imports_filesystem_api_cluster`
- `contains_ransom_note_keyword`
- `contains_extension_change_keyword`
- `contains_backup_delete_command`
- `contains_recovery_disable_command`
- `contains_onion_or_wallet_indicator`
- `contains_config_like_string`

### 9.3 Tool-To-Feature Mapping Guidance

| Source Observation | Normalized Feature |
|---|---|
| DIE reports packer or obfuscator | `packed_binary` |
| PE sections exceed entropy threshold | `high_entropy_sections` |
| imports include crypto-related APIs | `imports_crypto_api` |
| strings include ransom-note text | `contains_ransom_note_keyword` |
| strings include `vssadmin` or similar deletion commands | `contains_backup_delete_command` |
| strings include recovery-disabling commands | `contains_recovery_disable_command` |

### 9.4 Boolean vs Count Normalization

Recommended rules:
- semantic presence indicators use boolean form in `matched_features`
- raw numeric observations stay in structured subfields

Example:
- `crypto_api_count = 4`
- `matched_features` contains `imports_crypto_api`

### 9.5 Entropy Normalization Draft

Phase-1 suggested section entropy rule:
- section entropy `>= 7.2` counts as high entropy

Normalization:
- store raw count in `high_entropy_sections`
- add `high_entropy_sections` to `matched_features` only if count is meaningful, for example `>= 2`

### 9.6 String Keyword Normalization

Phase-1 string matching should normalize matched text into feature classes rather than preserve all raw text as verdict features.

Recommended keyword classes:
- ransom-note class
- extension-change class
- backup-delete class
- recovery-disable class
- onion-or-wallet class

Raw matched strings may still be stored under `string_features`, but verdict logic should depend on normalized feature names.

## 10. Dynamic Event Naming And Normalization Rules

The dynamic-analysis module should normalize runtime observations into a stable event vocabulary.

### 10.1 Naming Principles

- use lowercase snake_case
- separate raw events from normalized behavioral features
- prefer behavior meaning over collector-specific wording

### 10.2 Phase-1 Raw Event Fields

Raw event objects should stay simple and collector-neutral.

Recommended process-event fields:
- `process_name`
- `parent_process`
- `child_process_count`
- `command_line`
- `suspicious_spawn`

Recommended file-event fields:
- `created_count`
- `modified_count`
- `renamed_count`
- `deleted_count`
- `high_frequency_write`
- `target_extensions`

### 10.3 Normalized Dynamic Feature Names

Recommended phase-1 normalized names:
- `process_execution_observed`
- `suspicious_child_process_spawn`
- `bulk_file_create`
- `bulk_file_modify`
- `bulk_file_rename`
- `high_frequency_write`
- `targeted_user_file_extensions`
- `execution_timeout`
- `execution_failed`

### 10.4 Event-To-Feature Mapping Guidance

| Raw Observation | Normalized Feature |
|---|---|
| sample process starts successfully | `process_execution_observed` |
| suspicious child process chain appears | `suspicious_child_process_spawn` |
| many file creations in window | `bulk_file_create` |
| many file modifications in window | `bulk_file_modify` |
| many renames in window | `bulk_file_rename` |
| dense write pattern in short time | `high_frequency_write` |
| user-document extensions repeatedly touched | `targeted_user_file_extensions` |
| sample hits observation timeout | `execution_timeout` |
| sample cannot be launched | `execution_failed` |

### 10.5 Phase-1 Count Threshold Draft

These are operational drafts and may be tuned later.

Suggested dynamic count thresholds:
- `created_count >= 20` may indicate `bulk_file_create`
- `modified_count >= 20` may indicate `bulk_file_modify`
- `renamed_count >= 10` may indicate `bulk_file_rename`

Suggested high-frequency-write hint:
- dense write events concentrated within a short sub-window of the total observation period

### 10.6 Extension Normalization

For phase 1, `target_extensions` should be normalized to lowercase and deduplicated.

Recommended focus classes:
- document extensions
- image extensions
- archive extensions
- database-like extensions

The module does not need full family-specific targeting logic in phase 1.

### 10.7 Dynamic Summary Normalization

`summary` should be compact and behavior-oriented.

Recommended patterns:
- `sample executed and modified files at high frequency`
- `sample executed but no strong file behavior was observed`
- `dynamic execution failed before behavior collection`

## 11. Phase-1 Directory Structure And File Organization

The phase-1 project layout should prioritize clarity, traceability, and easy batch expansion.

### 11.1 Recommended Top-Level Layout

```text
project-root/
├── ransomware/                     # malware sample set
├── benign/                         # optional benign sample set
├── project-memory/                 # long-term project memory and formal plans
├── skills/                         # project-local skills
├── configs/                        # runtime and tool configuration
├── schemas/                        # JSON schema or result-field references
├── results/                        # analysis outputs
├── logs/                           # runtime logs
├── staging/                        # temporary per-run files
└── src/ or app/                    # implementation code, to be decided later
```

### 11.2 Recommended `results/` Layout

```text
results/
├── single/                         # single-sample runs
├── batch/                          # batch runs
├── summaries/                      # aggregated summaries
└── failed/                         # degraded or failed workflow results
```

### 11.3 Recommended `logs/` Layout

```text
logs/
├── single/
├── batch/
└── agent/
```

### 11.4 Recommended `staging/` Layout

```text
staging/
├── uploads/
├── extracted_strings/
├── static_raw/
└── dynamic_raw/
```

Guidance:
- `staging/` is temporary and should not be treated as final evidence storage
- normalized outputs belong in `results/`

### 11.5 File Organization Principles

- keep raw intermediate data separated from normalized outputs
- one sample should map to one primary JSON result
- batch runs should produce both per-sample JSON and an aggregate summary
- failed workflows should still emit structured outputs

## 12. Result File Naming Rules

Phase 1 should use deterministic and collision-resistant result names.

### 12.1 Single-Sample Result Naming

Recommended filename pattern:

```text
{timestamp}__{sha256_prefix}__{mode}.json
```

Example:

```text
20260428T103000+0800__e10cae894e88__single.json
```

Fields:
- `timestamp`: workflow start time
- `sha256_prefix`: first 12 to 16 characters of SHA256
- `mode`: `single` or `batch`

### 12.2 Batch Result Naming

Recommended per-sample filename pattern:

```text
{batch_id}__{sha256_prefix}.json
```

Recommended aggregate summary filename:

```text
{batch_id}__summary.json
```

Example:

```text
batch-20260428-01__e10cae894e88.json
batch-20260428-01__summary.json
```

### 12.3 Failed Or Degraded Result Naming

If a workflow fails early, still emit a result file:

```text
{timestamp}__{sample_hint}__failed.json
```

Where `sample_hint` may be:
- SHA256 prefix if available
- filename stem if hash calculation failed

### 12.4 Log Naming

Recommended log filename pattern:

```text
{timestamp}__{sha256_prefix}__workflow.log
```

Agent-specific trace logs may use:

```text
{timestamp}__{sha256_prefix}__agent.log
```

### 12.5 Naming Rules

- use ASCII-only names
- avoid spaces
- normalize timestamps consistently
- prefer SHA256 prefix over original filename for stable identity

## 13. Execution Flow From Single Sample To Batch

Phase 1 should expand execution scope incrementally.

### 13.1 Stage A: Single-Sample Closed Loop

Objective:
- validate one complete workflow end to end

Input:
- one VT-confirmed malicious sample

Expected outputs:
- one complete JSON result
- one workflow log
- one agent trace

Exit criteria:
- all core modules execute
- final JSON is structurally complete
- errors, if any, are properly normalized

### 13.2 Stage B: Small-Batch Closed Loop

Objective:
- validate workflow stability across multiple samples

Input:
- a small set of VT high-confidence malicious samples
- a small benign set for initial false-positive observation

Recommended initial size:
- malicious: `5-20`
- benign: `3-10`

Expected outputs:
- one JSON per sample
- one batch summary JSON
- batch logs

Batch summary should include:
- total sample count
- successful workflow count
- degraded workflow count
- label distribution
- average runtime

### 13.3 Stage C: Expanded Batch

Objective:
- prepare for broader experimental execution

Input:
- larger malicious subset
- optional larger benign subset

Focus:
- runtime stability
- output completeness
- repeatability

### 13.4 Single-Sample Workflow Procedure

Recommended procedure:
1. select one VT-confirmed malicious sample
2. initialize workflow context
3. calculate hashes and query VT
4. record first Agent decision
5. execute static analysis
6. record second Agent decision
7. execute dynamic analysis
8. produce final verdict
9. write JSON and logs
10. verify result completeness

### 13.5 Small-Batch Workflow Procedure

Recommended procedure:
1. prepare a batch list
2. assign a `batch_id`
3. run the single-sample pipeline independently for each sample
4. persist per-sample JSON files
5. collect failures without stopping the whole batch
6. generate batch summary JSON
7. review degraded workflows separately

### 13.6 Batch Execution Rules

- batch execution should not stop because one sample fails
- each sample must have an independent result file
- batch summary must distinguish:
  - success
  - partial
  - failed
- failed samples should be easy to re-run individually later

### 13.7 Re-run Rules

Suggested re-run cases:
- VT transient failure
- VM execution timeout
- partial static or dynamic outputs

Suggested re-run policy for phase 1:
- allow at most one automatic re-run for recoverable failures
- record original failure in logs even if re-run succeeds

## 14. Batch Summary JSON Fields

Each batch run should produce one aggregate summary file.

### 14.1 Recommended Summary Structure

```json
{
  "batch_id": "",
  "runtime": {},
  "input_stats": {},
  "workflow_stats": {},
  "label_stats": {},
  "module_stats": {},
  "failure_stats": {},
  "artifacts": {}
}
```

### 14.2 Required Fields

`batch_id`
- unique batch identifier

`runtime`
- `start_time`
- `end_time`
- `duration_sec`
- `phase`

`input_stats`
- `total_samples`
- `malicious_set_count`
- `benign_set_count`

`workflow_stats`
- `successful_count`
- `partial_count`
- `failed_count`
- `rerun_count`
- `avg_duration_sec`

`label_stats`
- `malicious_count`
- `suspicious_count`
- `benign_count`

`module_stats`
- `vt_ok_count`
- `vt_error_count`
- `static_ok_count`
- `static_partial_count`
- `static_error_count`
- `dynamic_ok_count`
- `dynamic_partial_count`
- `dynamic_error_count`

`failure_stats`
- `fatal_count`
- `recoverable_count`
- `partial_issue_count`
- `top_error_codes`

`artifacts`
- `result_dir`
- `log_dir`
- `failed_dir`
- `summary_version`

### 14.3 Recommended Optional Fields

- `sample_results`: list of per-sample result file paths
- `degraded_samples`: list of samples with partial or failed workflows
- `notes`

### 14.4 Summary Principles

- the summary should support quick experiment review
- the summary should not replace per-sample JSON
- the summary should make degraded workflows easy to identify

## 15. Logging Fields And Log Levels

Phase 1 should log enough to support debugging and experiment traceability without overwhelming the output.

### 15.1 Recommended Log Levels

- `DEBUG`
- `INFO`
- `WARN`
- `ERROR`

Suggested use:
- `DEBUG`: raw intermediate details for development
- `INFO`: workflow progress and normal stage transitions
- `WARN`: partial failures and recoverable anomalies
- `ERROR`: module failures and fatal workflow issues

### 15.2 Per-Entry Log Fields

Recommended fields for structured logs:
- `timestamp`
- `level`
- `workflow_id`
- `batch_id`
- `sample_id`
- `stage`
- `event`
- `message`
- `error_code`
- `details`

Where:
- `sample_id` should prefer SHA256 prefix
- `error_code` may be empty for non-error entries
- `details` should be compact JSON-like metadata

### 15.3 Recommended Stage Values For Logs

- `sample_ingest`
- `hash_intel`
- `agent_decision_1`
- `static_analysis`
- `agent_decision_2`
- `dynamic_analysis`
- `final_verdict`
- `result_recorder`
- `batch_summary`

### 15.4 Recommended Event Values

- `workflow_started`
- `module_started`
- `module_completed`
- `module_partial`
- `module_failed`
- `rerun_started`
- `rerun_completed`
- `verdict_emitted`
- `summary_written`

### 15.5 Logging Principles

- every module start should emit one `INFO`
- every module end should emit one `INFO`
- every recoverable issue should emit one `WARN`
- every fatal stop should emit one `ERROR`
- reruns must be explicitly logged

### 15.6 Agent Log Guidance

Agent-specific logs should capture:
- decision point
- selected next action
- key supporting evidence summary
- why the path was not terminated early in phase 1

### 15.7 Log Retention Guidance

Phase-1 recommendation:
- retain logs for all single-sample and small-batch runs
- allow later pruning of `DEBUG` logs if storage becomes noisy

## 16. Re-run Strategy And De-duplication Rules

Phase 1 should support cautious re-runs while avoiding duplicate experimental records.

### 16.1 Re-run Eligibility

Allow automatic re-run only for recoverable or partial failures such as:
- VT timeout
- VT temporary quota or network failure
- VM timeout
- incomplete dynamic event export
- partial static tool availability

Do not auto-rerun for:
- missing sample file
- unreadable sample file
- unsupported input type
- repeated deterministic parser failure

### 16.2 Re-run Limit

Recommended phase-1 rule:
- at most one automatic re-run per sample per workflow launch

If the re-run also fails:
- preserve the degraded result
- do not loop further automatically

### 16.3 Re-run Recording Rules

When a re-run happens:
- keep the original failure in logs
- add rerun events to logs
- store rerun count in the final per-sample JSON or runtime metadata
- mark whether the final result came from the initial run or rerun

Recommended runtime metadata additions:
- `rerun_count`
- `final_attempt`

### 16.4 De-duplication Identity

Recommended primary identity:
- `sha256`

Secondary identity:
- normalized sample path

Reason:
- filenames may change
- hashes are more stable across runs

### 16.5 De-duplication Rules

For phase 1:
- do not process the same `sha256` twice within one batch unless explicitly requested
- if duplicates appear in the input list, keep only the first occurrence for execution
- record duplicate skips in the batch summary

Recommended summary additions:
- `duplicate_input_count`
- `duplicate_skipped_count`

### 16.6 Result Replacement Rules

If a sample is re-run:
- the current workflow should keep one final canonical result file
- previous attempts may be retained in logs or staging records
- the final JSON should reflect the last effective attempt

### 16.7 Manual Re-run Rules

Manual re-runs should be allowed when:
- the environment has been fixed
- thresholds have changed and the user wants comparison
- a degraded sample needs targeted validation

Recommended manual re-run behavior:
- generate a new `workflow_id`
- keep `sha256` identity unchanged
- do not overwrite prior batch summaries

## 17. Configuration File Design

Phase 1 should centralize tunable values in configuration files instead of scattering them across code.

### 17.1 Recommended Config Layout

```text
configs/
├── phase1.yaml
├── virustotal.yaml
├── static-analysis.yaml
├── dynamic-analysis.yaml
└── logging.yaml
```

### 17.2 `phase1.yaml`

Purpose:
- store workflow-wide defaults

Recommended fields:
- `phase_name`
- `default_mode`
- `observation_window_sec`
- `allow_auto_rerun`
- `max_auto_rerun`
- `enable_batch_dedup`
- `results_dir`
- `logs_dir`
- `staging_dir`

### 17.3 `virustotal.yaml`

Purpose:
- store threat-intelligence query behavior

Recommended fields:
- `enabled`
- `api_key_env`
- `query_hash_priority`
- `timeout_sec`
- `retry_enabled`
- `retry_count`
- `rate_limit_sleep_sec`

### 17.4 `static-analysis.yaml`

Purpose:
- store static-tool settings and scoring thresholds

Recommended fields:
- `enabled_tools`
- `entropy_threshold`
- `high_entropy_section_count_threshold`
- `string_keyword_sets`
- `score_weights`
- `medium_score_threshold`
- `high_score_threshold`

### 17.5 `dynamic-analysis.yaml`

Purpose:
- store dynamic-environment and event-threshold settings

Recommended fields:
- `environment_type`
- `snapshot_name`
- `network_mode`
- `observation_window_sec`
- `process_event_enabled`
- `file_event_enabled`
- `bulk_create_threshold`
- `bulk_modify_threshold`
- `bulk_rename_threshold`
- `high_write_density_threshold`
- `timeout_sec`

### 17.6 `logging.yaml`

Purpose:
- store log behavior and retention settings

Recommended fields:
- `log_level`
- `structured_logging`
- `log_dir`
- `retain_debug_logs`
- `separate_agent_log`

### 17.7 Config Principles

- configuration should be phase-scoped, not hardcoded
- secrets should not be written directly into repo files
- API credentials should be referenced via environment variables
- thresholds should be easy to revise between experimental rounds

## 18. Module Status Codes And Error Codes

Phase 1 should use a small and consistent status/error vocabulary.

### 18.1 Status Codes

Recommended module-level status codes:

| Status | Meaning |
|---|---|
| `ok` | module completed successfully |
| `partial` | module completed with incomplete evidence |
| `error` | module failed but workflow may still continue |
| `fatal` | workflow cannot continue meaningfully |
| `skipped` | module intentionally not executed |

### 18.2 Workflow-Level Status

Recommended workflow-level status values:

| Status | Meaning |
|---|---|
| `completed` | workflow reached final verdict normally |
| `completed_degraded` | workflow reached final verdict with partial failures |
| `failed_early` | workflow stopped before meaningful analysis |

### 18.3 Recommended Error Code Prefixes

- `INPUT_*`
- `VT_*`
- `STATIC_*`
- `DYNAMIC_*`
- `VERDICT_*`
- `RESULT_*`
- `BATCH_*`

### 18.4 Input Error Codes

Recommended:
- `INPUT_FILE_NOT_FOUND`
- `INPUT_FILE_UNREADABLE`
- `INPUT_UNSUPPORTED_TYPE`

### 18.5 Threat-Intel Error Codes

Recommended:
- `VT_TIMEOUT`
- `VT_RATE_LIMIT`
- `VT_NETWORK_FAILURE`
- `VT_SCHEMA_PARSE_FAILURE`
- `VT_EMPTY_RESPONSE`

### 18.6 Static-Analysis Error Codes

Recommended:
- `STATIC_PE_PARSE_FAILURE`
- `STATIC_STRINGS_FAILURE`
- `STATIC_DIE_UNAVAILABLE`
- `STATIC_TOOL_TIMEOUT`
- `STATIC_EMPTY_OUTPUT`

### 18.7 Dynamic-Analysis Error Codes

Recommended:
- `DYNAMIC_VM_BOOT_FAILURE`
- `DYNAMIC_EXECUTION_TIMEOUT`
- `DYNAMIC_SAMPLE_LAUNCH_FAILURE`
- `DYNAMIC_EVENT_EXPORT_FAILURE`
- `DYNAMIC_ENVIRONMENT_UNAVAILABLE`

### 18.8 Verdict And Result Error Codes

Recommended:
- `VERDICT_INSUFFICIENT_EVIDENCE`
- `RESULT_JSON_WRITE_FAILURE`
- `RESULT_SUMMARY_WRITE_FAILURE`

### 18.9 Error-Code Principles

- one failure reason should map to one stable error code
- error codes should be concise and machine-friendly
- human-readable explanation belongs in `message`, not in the code itself

## 19. Phase-1 Experimental Metrics

Phase 1 metrics should focus on workflow validation first, with basic detection statistics as secondary support.

### 19.1 Primary Phase-1 Metrics

Recommended primary metrics:
- workflow completion rate
- degraded workflow rate
- average runtime per sample
- batch runtime stability
- Agent trace completeness

Definitions:

| Metric | Meaning |
|---|---|
| `workflow_completion_rate` | fraction of samples reaching final verdict |
| `degraded_workflow_rate` | fraction of samples reaching verdict with partial failures |
| `avg_runtime_per_sample` | average end-to-end runtime |
| `batch_runtime_stability` | runtime dispersion across a batch |
| `agent_trace_completeness` | whether required decision trace fields are present |

### 19.2 Secondary Detection Metrics

Recommended secondary metrics:
- `malicious_recall`
- `benign_false_positive_observation`
- `suspicious_output_rate`

Notes:
- in phase 1, these are observational rather than final benchmark metrics
- the benign set is still small, so false-positive interpretation should stay cautious

### 19.3 Module Reliability Metrics

Recommended:
- `vt_query_success_rate`
- `static_module_success_rate`
- `dynamic_module_success_rate`
- `result_write_success_rate`
- `auto_rerun_trigger_rate`

### 19.4 Batch Summary Metrics

Recommended fields for later summary aggregation:
- `total_samples`
- `successful_count`
- `partial_count`
- `failed_count`
- `rerun_count`
- `duplicate_skipped_count`
- `label_distribution`
- `avg_duration_sec`

### 19.5 Trace Quality Metrics

Recommended:
- percentage of samples with complete `agent_trace`
- percentage of samples with complete `score_breakdown`
- percentage of samples with normalized `error_code` when failures occur

### 19.6 Phase-1 Success Interpretation

Phase 1 should be considered successful if:
- single-sample workflow runs end to end
- small-batch workflow is stable
- most samples produce structured JSON successfully
- degraded cases remain traceable
- Agent path records are complete enough for later comparison

## 20. Batch Summary Formulas

Phase-1 summary metrics should use simple and stable formulas.

### 20.1 Core Count Formulas

Let:
- `N_total` = total input samples after de-duplication
- `N_success` = workflows with normal completion
- `N_partial` = workflows completed in degraded mode
- `N_failed` = workflows that failed early
- `N_rerun` = workflows that triggered one automatic re-run

Recommended formulas:
- `workflow_completion_rate = (N_success + N_partial) / N_total`
- `degraded_workflow_rate = N_partial / N_total`
- `failed_early_rate = N_failed / N_total`
- `auto_rerun_trigger_rate = N_rerun / N_total`

### 20.2 Runtime Formulas

Let:
- `T_i` = runtime of sample `i`
- `N_completed` = number of completed or degraded workflows

Recommended formulas:
- `avg_runtime_per_sample = sum(T_i) / N_completed`
- `max_runtime = max(T_i)`
- `min_runtime = min(T_i)`

Recommended stability indicator:
- `runtime_range = max_runtime - min_runtime`

Optional later extension:
- standard deviation of runtime

### 20.3 Label Distribution Formulas

Let:
- `N_malicious`
- `N_suspicious`
- `N_benign`

Recommended formulas:
- `malicious_ratio = N_malicious / N_total`
- `suspicious_ratio = N_suspicious / N_total`
- `benign_ratio = N_benign / N_total`

### 20.4 Module Reliability Formulas

Threat-intel:
- `vt_query_success_rate = N_vt_ok / N_total`
- `vt_query_error_rate = N_vt_error / N_total`

Static module:
- `static_module_success_rate = N_static_ok / N_total`
- `static_module_partial_rate = N_static_partial / N_total`
- `static_module_error_rate = N_static_error / N_total`

Dynamic module:
- `dynamic_module_success_rate = N_dynamic_ok / N_total`
- `dynamic_module_partial_rate = N_dynamic_partial / N_total`
- `dynamic_module_error_rate = N_dynamic_error / N_total`

### 20.5 Trace Quality Formulas

Let:
- `N_trace_complete` = samples with required `agent_trace` fields complete
- `N_score_breakdown_complete` = samples with score breakdown present where applicable
- `N_error_normalized` = failed or partial samples with normalized `error_code`

Recommended formulas:
- `agent_trace_completeness = N_trace_complete / N_total`
- `score_breakdown_completeness = N_score_breakdown_complete / N_total`
- `error_normalization_rate = N_error_normalized / max(1, N_partial + N_failed)`

### 20.6 Benign Observation Formula

If a small benign set exists:

Let:
- `N_benign_input` = benign samples in the batch
- `N_benign_flagged` = benign samples classified as `malicious` or `suspicious`

Recommended observational metric:
- `benign_false_positive_observation = N_benign_flagged / max(1, N_benign_input)`

## 21. Static And Dynamic Scoring Weight Tables

Phase 1 should use interpretable heuristic weighting.

### 21.1 Static Scoring Structure

Recommended composition:
- `static_score = 0.3 * pe_score + 0.3 * import_score + 0.4 * string_score`

### 21.2 Static Feature Weight Draft

Recommended feature-level draft:

| Normalized Feature | Suggested Weight | Notes |
|---|---|---|
| `contains_ransom_note_keyword` | `0.35` | strongest phase-1 static indicator |
| `contains_backup_delete_command` | `0.25` | strong destructive intent hint |
| `contains_recovery_disable_command` | `0.20` | strong destructive intent hint |
| `imports_crypto_api` | `0.20` | useful but not sufficient alone |
| `imports_shadowcopy_or_recovery_api` | `0.20` | high-value supporting signal |
| `packed_binary` | `0.15` | supportive, not decisive |
| `high_entropy_sections` | `0.15` | supportive, not decisive |
| `contains_extension_change_keyword` | `0.15` | useful supporting string signal |
| `contains_onion_or_wallet_indicator` | `0.15` | family-dependent support |
| `contains_config_like_string` | `0.10` | weak supporting signal |
| `suspicious_timestamp` | `0.05` | very weak standalone signal |
| `entrypoint_anomaly` | `0.05` | weak standalone signal |

Guidance:
- use capped accumulation so repeated weak signals do not dominate
- phase-1 scoring should stay simple and bounded

### 21.3 Static Subscore Guidance

Suggested qualitative approach:
- `pe_score` from packing/entropy/entry anomalies
- `import_score` from suspicious import clusters
- `string_score` from ransom-note and destructive command evidence

Recommended intuition:
- string-based evidence should be slightly stronger than PE-only evidence in phase 1

### 21.4 Dynamic Scoring Structure

Recommended composition:
- `dynamic_score = 0.4 * process_score + 0.6 * file_score`

### 21.5 Dynamic Feature Weight Draft

| Normalized Feature | Suggested Weight | Notes |
|---|---|---|
| `bulk_file_rename` | `0.30` | strong ransomware-like signal |
| `high_frequency_write` | `0.30` | strong file-impact signal |
| `bulk_file_modify` | `0.25` | strong supporting signal |
| `targeted_user_file_extensions` | `0.20` | useful targeting indicator |
| `bulk_file_create` | `0.15` | weaker than rename/modify for phase 1 |
| `suspicious_child_process_spawn` | `0.20` | process-level support |
| `process_execution_observed` | `0.05` | confirms execution only |
| `execution_timeout` | `0.05` | weak support, may be environment-related |
| `execution_failed` | `0.00` | should not be treated as malicious evidence alone |

### 21.6 Weighting Principles

- destructive or encryption-like file behavior should outweigh weak process anomalies
- execution failure alone should not increase maliciousness
- repeated medium-strength file evidence may justify `suspicious` even without high VT support

## 22. Agent Prompting And Decision Input Format

Phase 1 Agent behavior should be constrained and structured.

### 22.1 Agent Role In Phase 1

The Agent should:
- choose the next action
- explain why the action was chosen
- summarize evidence for later traceability

The Agent should not:
- bypass the phase-1 full-workflow rule
- invent unavailable evidence
- depend on raw tool-specific schema details

### 22.2 Recommended Agent Input Object

The Agent should receive a normalized input object shaped like:

```json
{
  "phase": "phase_1_full_workflow_validation",
  "policy": {
    "no_early_termination": true,
    "prefer_full_workflow": true
  },
  "sample": {
    "sha256": "",
    "file_type": "",
    "file_size": 0
  },
  "threat_intel": {
    "status": "",
    "matched": false,
    "vt_signal": "unknown",
    "label": "unknown",
    "summary": ""
  },
  "static_analysis": {
    "status": "skipped",
    "risk_score": null,
    "matched_features": []
  },
  "dynamic_analysis": {
    "status": "skipped",
    "risk_score": null,
    "matched_features": []
  },
  "history": {
    "completed_stages": [],
    "last_decision": null
  }
}
```

### 22.3 Recommended Agent Output Object

The Agent should return a compact normalized decision object:

```json
{
  "next_action": "static_analysis",
  "decision": "continue_to_static",
  "reason": "Phase 1 requires full workflow coverage and static evidence is not yet collected",
  "confidence": 0.88,
  "evidence_summary": [
    "VT result available",
    "Static analysis not yet executed"
  ]
}
```

### 22.4 Allowed `next_action` Values

- `static_analysis`
- `dynamic_analysis`
- `final_verdict`

### 22.5 Allowed `decision` Values

- `continue_to_static`
- `continue_to_dynamic`
- `continue_full_workflow`
- `continue_after_vt_error`
- `continue_after_static_error`
- `continue_after_dynamic_error`
- `produce_final_verdict`
- `emit_degraded_verdict`

### 22.6 Agent Prompt Constraints

Recommended prompt constraints:
- always honor current phase policy
- prefer normalized evidence over raw output
- keep reasons short and concrete
- mention missing evidence when applicable
- do not output free-form narratives longer than needed

### 22.7 Decision Prompt Template Draft

Recommended prompt shape:

```text
You are the phase-1 orchestration agent for ransomware analysis.
Your job is to choose the next action using only the normalized input.
Current policy:
- no early termination
- prefer full workflow coverage

Choose exactly one next action from:
- static_analysis
- dynamic_analysis
- final_verdict

Return:
- next_action
- decision
- reason
- confidence
- evidence_summary
```

### 22.8 Final Verdict Prompt Template Draft

Recommended prompt shape:

```text
You are the phase-1 verdict agent.
Use normalized threat-intelligence, static, and dynamic evidence.
Return exactly:
- final_label
- final_score
- decision_basis
- explanation

Allowed labels:
- malicious
- suspicious
- benign
```

## 23. Phase-1 Incremental Implementation Plan

Phase 1 should be implemented in small, verifiable slices.

### 23.1 Development Order

Recommended order:
1. result schema and recorder
2. sample ingest
3. hash and VT lookup
4. Agent skeleton and trace writer
5. static analysis pipeline
6. verdict engine
7. dynamic analysis pipeline
8. batch runner
9. batch summary generation

Rationale:
- outputs should be stabilized before more modules depend on them
- traceability should exist before orchestration grows
- dynamic analysis should come after the single-sample control path is already stable

### 23.2 Milestone M1: Result Skeleton

Goal:
- make it possible to emit a structurally valid phase-1 JSON

Includes:
- result schema constants or references
- empty/default field initialization
- result-recorder write path
- workflow metadata generation

Exit criteria:
- one dummy workflow can write a valid JSON artifact

### 23.3 Milestone M2: Sample Ingest + Hash Intelligence

Goal:
- process one real sample through ingest and VT lookup

Includes:
- sample path validation
- file metadata extraction
- MD5/SHA1/SHA256 calculation
- VT query integration
- VT normalization

Exit criteria:
- one real sample produces `sample` and `threat_intel` sections correctly

### 23.4 Milestone M3: Agent Skeleton

Goal:
- make routing and trace generation deterministic

Includes:
- normalized Agent input object
- normalized Agent output object
- initial decision policy
- `agent_trace` append logic

Exit criteria:
- workflow can produce a decision after VT lookup and record it

### 23.5 Milestone M4: Static Analysis

Goal:
- complete the first evidence-producing branch

Includes:
- `pefile`
- `strings`
- `DIE`
- feature normalization
- static scoring

Exit criteria:
- one sample produces `static_analysis` with normalized features and score

### 23.6 Milestone M5: Verdict Engine

Goal:
- emit a stable three-class verdict before dynamic integration

Includes:
- normalized verdict input adapter
- verdict rules
- final explanation generation

Exit criteria:
- workflow can produce a complete verdict from VT + static-only inputs

### 23.7 Milestone M6: Dynamic Analysis

Goal:
- add phase-1 runtime evidence collection

Includes:
- VM execution wrapper
- process/file event collection
- dynamic feature normalization
- dynamic scoring

Exit criteria:
- one sample produces `dynamic_analysis` with normalized events and score

### 23.8 Milestone M7: Full Single-Sample Closed Loop

Goal:
- complete the end-to-end phase-1 pipeline

Includes:
- all prior modules connected
- full workflow logging
- final result persistence

Exit criteria:
- one VT-confirmed malicious sample completes full workflow successfully

### 23.9 Milestone M8: Small-Batch Execution

Goal:
- validate workflow stability on multiple samples

Includes:
- batch input handling
- per-sample isolation
- per-sample result persistence
- batch summary generation
- duplicate filtering

Exit criteria:
- one small batch finishes with summary output and no uncontrolled crashes

## 24. Phase-1 Test Plan

Phase 1 testing should prioritize correctness of workflow structure and resilience of module boundaries.

### 24.1 Test Layers

Recommended layers:
- schema tests
- module unit tests
- normalization tests
- workflow integration tests
- batch behavior tests

### 24.2 Schema Tests

Purpose:
- ensure all result files conform to the required structure

Recommended checks:
- required top-level keys exist
- required nested fields exist
- enum-like fields use allowed values
- partial and error outputs still remain structurally valid

### 24.3 Module Unit Tests

Recommended targets:
- hash calculation
- VT normalization
- static feature normalization
- dynamic event normalization
- verdict mapping
- result filename generation

Recommended checks:
- deterministic output from fixed inputs
- correct status/error handling
- threshold boundaries behave as expected

### 24.4 Normalization Tests

Purpose:
- ensure different raw tool outputs map into the same normalized vocabulary

Recommended targets:
- VT no-hit vs VT error
- DIE packer detection mapping
- strings keyword mapping
- file-event threshold mapping

### 24.5 Integration Tests

Recommended scenarios:
- single-sample successful run
- VT error with static fallback
- static partial with dynamic continuation
- dynamic timeout with degraded verdict
- result write success after degraded workflow

### 24.6 Batch Tests

Recommended scenarios:
- duplicate sample paths in one batch
- one sample fails, others continue
- batch summary counts match per-sample outcomes
- rerun count recorded correctly

### 24.7 Manual Validation Checklist

Before considering phase 1 ready:
- inspect one full malicious-sample JSON manually
- inspect one benign-sample JSON manually
- inspect one degraded-result JSON manually
- inspect one batch summary manually
- confirm `agent_trace` reasons are readable and concrete

### 24.8 Minimum Test Gate For Implementation Progress

Recommended minimum gate before moving to larger batches:
- schema tests pass
- one successful malicious single-sample run
- one degraded path validated
- one small-batch summary validated

## 25. Repository Structure Draft

Phase 1 code organization should reflect the normalized pipeline and allow later expansion.

### 25.1 Recommended Layout

```text
project-root/
├── AGENT-RULES.md
├── ransomware/
├── benign/
├── configs/
├── logs/
├── project-memory/
├── results/
├── schemas/
├── skills/
├── staging/
└── src/
    ├── core/
    │   ├── context/
    │   ├── models/
    │   └── utils/
    ├── ingest/
    ├── intel/
    ├── agent/
    ├── static_analysis/
    ├── dynamic_analysis/
    ├── verdict/
    ├── recorder/
    ├── batch/
    └── cli/
```

### 25.2 Module Responsibilities

`core/`
- shared data structures
- workflow context helpers
- common utilities

`ingest/`
- sample path handling
- file metadata collection
- hash calculation if not placed under shared utilities

`intel/`
- VT client
- VT normalization

`agent/`
- decision input builder
- decision prompt wrapper
- trace writer

`static_analysis/`
- PE parsing
- string extraction
- DIE integration
- feature normalization
- static scoring

`dynamic_analysis/`
- VM runner
- event collector adapter
- event normalization
- dynamic scoring

`verdict/`
- final decision rules
- final score composition
- explanation generation

`recorder/`
- JSON writer
- path naming
- summary writing

`batch/`
- batch orchestration
- duplicate filtering
- rerun logic
- summary aggregation

`cli/`
- single-sample command entry
- batch command entry

### 25.3 Test Layout Draft

Recommended:

```text
tests/
├── schema/
├── unit/
├── integration/
└── fixtures/
```

Where:
- `schema/` validates result structures
- `unit/` covers module logic
- `integration/` covers workflow slices
- `fixtures/` stores sanitized sample metadata or mocked outputs where possible

### 25.4 Repository Principles

- keep normalized logic close to each module
- avoid mixing raw collector output with final result objects
- isolate configuration from implementation
- keep batch logic separate from single-sample pipeline logic

## 26. CLI And Command Entry Design

Phase 1 should expose a small and explicit command surface.

### 26.1 Recommended CLI Modes

Recommended entry modes:
- single-sample analysis
- batch analysis
- summary generation
- result validation

### 26.2 Single-Sample Command Draft

Recommended shape:

```text
analyzer single --sample <path> --config <phase1-config>
```

Purpose:
- run one sample through the full phase-1 workflow

Recommended options:
- `--sample`
- `--config`
- `--output-dir`
- `--log-level`
- `--force-rerun`

### 26.3 Batch Command Draft

Recommended shape:

```text
analyzer batch --input-dir <dir> --config <phase1-config>
```

Alternative shape:

```text
analyzer batch --sample-list <file> --config <phase1-config>
```

Purpose:
- process a directory or explicit sample list

Recommended options:
- `--input-dir`
- `--sample-list`
- `--config`
- `--output-dir`
- `--batch-id`
- `--dedup`
- `--max-samples`

### 26.4 Summary Command Draft

Recommended shape:

```text
analyzer summary --batch-id <batch-id> --results-dir <dir>
```

Purpose:
- regenerate or verify one batch summary from per-sample results

### 26.5 Validation Command Draft

Recommended shape:

```text
analyzer validate-result --result <json-file>
```

Purpose:
- check whether one result file matches the expected schema

### 26.6 CLI Principles

- keep required arguments minimal
- prefer explicit paths over implicit discovery
- make single-sample mode the first stable path
- keep batch mode as a thin wrapper over the single-sample pipeline

## 27. Configuration File Example Draft

Phase 1 configuration should be readable and easy to tune between experimental rounds.

### 27.1 `phase1.yaml` Example Draft

```yaml
phase_name: phase_1_full_workflow_validation
default_mode: single
observation_window_sec: 60
allow_auto_rerun: true
max_auto_rerun: 1
enable_batch_dedup: true
results_dir: results
logs_dir: logs
staging_dir: staging
```

### 27.2 `virustotal.yaml` Example Draft

```yaml
enabled: true
api_key_env: VT_API_KEY
query_hash_priority:
  - sha256
  - sha1
  - md5
timeout_sec: 20
retry_enabled: true
retry_count: 1
rate_limit_sleep_sec: 15
```

### 27.3 `static-analysis.yaml` Example Draft

```yaml
enabled_tools:
  - pefile
  - strings
  - die

entropy_threshold: 7.2
high_entropy_section_count_threshold: 2

string_keyword_sets:
  ransom_note:
    - decrypt
    - your files
    - bitcoin
  backup_delete:
    - vssadmin
    - shadow copy
  recovery_disable:
    - bcdedit
    - recoveryenabled

score_weights:
  pe_score: 0.3
  import_score: 0.3
  string_score: 0.4

medium_score_threshold: 0.30
high_score_threshold: 0.60
```

### 27.4 `dynamic-analysis.yaml` Example Draft

```yaml
environment_type: windows_vm
snapshot_name: clean-baseline
network_mode: host_only
observation_window_sec: 60
process_event_enabled: true
file_event_enabled: true
bulk_create_threshold: 20
bulk_modify_threshold: 20
bulk_rename_threshold: 10
high_write_density_threshold: medium
timeout_sec: 90
```

### 27.5 `logging.yaml` Example Draft

```yaml
log_level: INFO
structured_logging: true
log_dir: logs
retain_debug_logs: false
separate_agent_log: true
```

### 27.6 Config Example Principles

- examples should reflect phase-1 defaults
- environment-specific secrets stay out of YAML
- thresholds should remain easy to edit between runs

## 28. External Result Report Format

Phase 1 should support a lightweight human-readable report in addition to raw JSON artifacts.

### 28.1 Reporting Goals

- allow quick manual review
- make single-sample and batch outcomes easy to present
- summarize Agent path and evidence without exposing raw internal details everywhere

### 28.2 Single-Sample Report Draft

Recommended sections:
- sample identity
- threat-intel summary
- Agent path summary
- static-analysis summary
- dynamic-analysis summary
- final verdict

Suggested shape:

```text
Sample: <sha256_prefix> (<file_name>)
VT: matched=<true/false>, malicious_count=<n>, label=<label>
Agent Path: hash_intel -> static_analysis -> dynamic_analysis -> final_verdict
Static: score=<x.xx>, matched_features=[...]
Dynamic: score=<x.xx>, matched_features=[...]
Verdict: <label> (score=<x.xx>)
Reason: <short explanation>
```

### 28.3 Batch Report Draft

Recommended sections:
- batch identity
- runtime summary
- workflow success/degraded/failed counts
- label distribution
- module reliability summary
- degraded sample list

Suggested shape:

```text
Batch: <batch_id>
Total Samples: <n>
Completed: <n>
Degraded: <n>
Failed Early: <n>
Labels: malicious=<n>, suspicious=<n>, benign=<n>
VT Success Rate: <x.xx>
Static Success Rate: <x.xx>
Dynamic Success Rate: <x.xx>
Degraded Samples: [...]
```

### 28.4 Report Generation Principles

- reports should be derived from normalized JSON outputs
- reports should not become the primary source of truth
- the JSON artifacts remain canonical

### 28.5 Phase-1 Presentation Guidance

For thesis or lab-progress communication, the following outputs are likely enough in phase 1:
- one sample-level report example
- one batch summary report
- one degraded-case report example

## 29. Core Data Model Skeleton Draft

Phase 1 should stabilize a small set of canonical workflow objects before implementation begins.

### 29.1 `AnalysisContext`

Purpose:
- the single canonical object passed across the pipeline

Suggested fields:
- `sample`
- `threat_intel`
- `agent_trace`
- `static_analysis`
- `dynamic_analysis`
- `verdict`
- `runtime`
- `workflow_status`

Recommended role:
- own the entire per-sample workflow state
- be the only object written by the recorder as the canonical result

### 29.2 `SampleInfo`

Suggested fields:
- `file_name`
- `file_path`
- `file_size`
- `file_type`
- `md5`
- `sha1`
- `sha256`
- `submitted_at`

Purpose:
- hold immutable sample identity and metadata

### 29.3 `ThreatIntelResult`

Suggested fields:
- `source`
- `query_hash_type`
- `query_hash_value`
- `matched`
- `vt_signal`
- `malicious_count`
- `suspicious_count`
- `harmless_count`
- `undetected_count`
- `reputation`
- `label`
- `permalink`
- `raw_summary`
- `status`
- `error`

Purpose:
- provide normalized intelligence evidence independent of raw VT schema

### 29.4 `AgentTraceItem`

Suggested fields:
- `step_id`
- `stage`
- `decision`
- `reason`
- `input_summary`
- `used_skill`
- `used_tool`
- `confidence`
- `timestamp`

Purpose:
- provide a stable audit trail of every major routing decision

### 29.5 `StaticAnalysisResult`

Suggested fields:
- `executed`
- `tools_used`
- `pe_features`
- `import_features`
- `string_features`
- `matched_features`
- `risk_score`
- `score_breakdown`
- `summary`
- `status`
- `error`

Purpose:
- carry normalized static evidence and heuristic scoring

### 29.6 `DynamicAnalysisResult`

Suggested fields:
- `executed`
- `environment`
- `tools_used`
- `execution_status`
- `process_events`
- `file_events`
- `matched_features`
- `risk_score`
- `score_breakdown`
- `summary`
- `status`
- `error`

Purpose:
- carry normalized dynamic evidence and heuristic scoring

### 29.7 `VerdictResult`

Suggested fields:
- `final_label`
- `final_score`
- `decision_basis`
- `explanation`

Purpose:
- represent the final normalized three-class output

### 29.8 `WorkflowRuntime`

Suggested fields:
- `workflow_id`
- `batch_id`
- `start_time`
- `end_time`
- `duration_sec`
- `phase`
- `rerun_count`
- `final_attempt`
- `notes`

Purpose:
- preserve workflow-level execution metadata

### 29.9 `WorkflowStatus`

Suggested fields:
- `status`
- `fatal`
- `error_code`
- `message`

Suggested values:
- `completed`
- `completed_degraded`
- `failed_early`

Purpose:
- give the outer workflow state a compact machine-readable shape

## 30. Single-Sample Workflow Skeleton Draft

Phase 1 should implement the single-sample path first and treat batch execution as a wrapper around it.

### 30.1 Canonical Workflow

```text
single_sample_workflow(sample_path):
  1. initialize runtime and empty AnalysisContext
  2. ingest sample metadata
  3. compute hashes
  4. query and normalize VT
  5. build Agent input and record decision #1
  6. run static analysis
  7. build Agent input and record decision #2
  8. run dynamic analysis
  9. compute final verdict
  10. finalize runtime
  11. write JSON result
```

### 30.2 Step Responsibilities

Step 1:
- create `workflow_id`
- initialize empty result objects with safe defaults

Step 2:
- validate sample path
- populate `SampleInfo`

Step 3:
- compute `md5`, `sha1`, `sha256`

Step 4:
- query VT
- populate `ThreatIntelResult`
- normalize `vt_signal`

Step 5:
- build normalized Agent input object
- record first routing decision

Step 6:
- execute static tools
- normalize features
- compute `static_score`

Step 7:
- rebuild Agent input using static evidence
- record second routing decision

Step 8:
- execute dynamic environment
- normalize dynamic events
- compute `dynamic_score`

Step 9:
- combine VT, static, and dynamic evidence
- emit `VerdictResult`

Step 10:
- compute total runtime
- assign final workflow status

Step 11:
- persist canonical JSON result

### 30.3 Suggested Function Boundary Draft

Suggested logical function boundaries:
- `initialize_context(sample_path)`
- `run_ingest(context)`
- `run_threat_intel(context)`
- `run_agent_decision(context, stage)`
- `run_static_analysis(context)`
- `run_dynamic_analysis(context)`
- `run_verdict(context)`
- `finalize_context(context)`
- `write_result(context)`

Guidance:
- each function should accept and return `AnalysisContext`
- each function should update only its owned portion plus workflow status metadata

### 30.4 Failure Behavior In Workflow Skeleton

Suggested behavior:
- fatal input failures stop the workflow early
- recoverable VT errors continue to static
- recoverable static errors continue to dynamic
- recoverable dynamic errors still allow degraded verdict output

## 31. Agent Layer Skeleton Draft

The Agent layer should remain narrow and normalized in phase 1.

### 31.1 Agent Layer Responsibilities

- build normalized decision input
- call the selected decision mechanism
- normalize decision output
- append one trace item

The Agent layer should not:
- directly parse raw VT or raw tool output
- own scoring logic
- own final result persistence

### 31.2 Suggested Agent Subcomponents

Recommended internal split:
- `input_builder`
- `decision_engine`
- `trace_writer`
- `policy_guard`

`input_builder`
- reads `AnalysisContext`
- emits normalized agent input object

`decision_engine`
- consumes normalized agent input
- returns normalized agent output

`trace_writer`
- converts decision output into `AgentTraceItem`

`policy_guard`
- ensures phase-1 rules are honored
- especially `no_early_termination`

### 31.3 Agent Input Skeleton

Recommended shape:

```json
{
  "phase": "phase_1_full_workflow_validation",
  "policy": {
    "no_early_termination": true,
    "prefer_full_workflow": true
  },
  "sample": {
    "sha256": "",
    "file_type": "",
    "file_size": 0
  },
  "threat_intel": {
    "status": "",
    "matched": false,
    "vt_signal": "unknown",
    "label": "unknown",
    "summary": ""
  },
  "static_analysis": {
    "status": "skipped",
    "risk_score": null,
    "matched_features": []
  },
  "dynamic_analysis": {
    "status": "skipped",
    "risk_score": null,
    "matched_features": []
  },
  "history": {
    "completed_stages": [],
    "last_decision": null
  }
}
```

### 31.4 Agent Output Skeleton

Recommended shape:

```json
{
  "next_action": "static_analysis",
  "decision": "continue_to_static",
  "reason": "Phase 1 requires static evidence before proceeding",
  "confidence": 0.88,
  "evidence_summary": [
    "VT result available",
    "Static analysis not yet executed"
  ]
}
```

### 31.5 Agent Trace Append Rule

Suggested append sequence:
1. Agent input built
2. decision returned
3. one `AgentTraceItem` appended to `context.agent_trace`

Recommended invariant:
- every routing decision must produce exactly one new trace item

### 31.6 Agent Stage Draft

Phase-1 routing stages:
- after VT result
- after static analysis

Optional later stage:
- before degraded final verdict in error-heavy cases

### 31.7 Agent Guardrails

The Agent layer must enforce:
- no direct `final_verdict` immediately after VT in phase 1
- no skipping trace generation
- no output labels outside `malicious / suspicious / benign` in verdict mode

## 32. Static Analysis Module Skeleton Draft

The static-analysis layer should remain tool-backed, normalized, and score-oriented in phase 1.

### 32.1 Static Layer Responsibilities

- invoke selected static tools
- collect raw tool outputs
- normalize raw outputs into stable feature names
- compute static risk score
- emit one `StaticAnalysisResult`

The static layer should not:
- execute the sample
- make final verdict decisions
- write canonical result JSON directly

### 32.2 Suggested Static Subcomponents

Recommended internal split:
- `tool_runner`
- `raw_collectors`
- `feature_normalizer`
- `score_calculator`
- `summary_builder`

`tool_runner`
- coordinates calls to `pefile`, `strings`, `DIE`

`raw_collectors`
- extract tool-specific raw data blobs

`feature_normalizer`
- maps raw observations to normalized phase-1 static features

`score_calculator`
- computes `pe_score`, `import_score`, `string_score`, and final `risk_score`

`summary_builder`
- produces concise human-readable summary text

### 32.3 Suggested Static Pipeline

```text
run_static_analysis(context):
  1. initialize empty StaticAnalysisResult
  2. execute PE parser
  3. execute strings extraction
  4. execute DIE or equivalent packer detector
  5. collect raw observations
  6. normalize features
  7. compute static scores
  8. build static summary
  9. update context.static_analysis
```

### 32.4 Suggested Static Function Boundary Draft

- `initialize_static_result()`
- `run_pe_parser(context)`
- `run_strings_extractor(context)`
- `run_packer_detector(context)`
- `normalize_static_features(raw_outputs)`
- `calculate_static_score(normalized_features)`
- `build_static_summary(normalized_features, scores)`
- `finalize_static_result()`

Guidance:
- tool invocation should be isolated from normalization logic
- normalization should be collector-agnostic
- score calculation should consume only normalized features

### 32.5 Suggested Static Raw Output Areas

Static raw outputs may be staged but should not become canonical evidence directly.

Recommended raw buckets:
- `raw_pe_metadata`
- `raw_imports`
- `raw_strings`
- `raw_die_report`

### 32.6 Suggested Static Failure Behavior

- if `pefile` fails:
  - record `STATIC_PE_PARSE_FAILURE`
  - continue with available string or DIE evidence if possible
- if `strings` fails:
  - record partial status
  - continue with PE and DIE evidence
- if `DIE` is unavailable:
  - mark partial and continue

Recommended invariant:
- if any useful static evidence exists, emit `StaticAnalysisResult` with `status=partial` instead of dropping the whole module result

### 32.7 Suggested Static Output Invariant

At module completion:
- `executed=true`
- `status in {ok, partial, error}`
- `risk_score` always present as numeric if normalization produced enough evidence
- `matched_features` contains only normalized feature names

## 33. Dynamic Analysis Module Skeleton Draft

The dynamic-analysis layer should remain execution-oriented, collector-neutral, and minimal in phase 1.

### 33.1 Dynamic Layer Responsibilities

- prepare the dynamic environment
- launch one sample in isolated execution
- collect minimal process and file events
- normalize runtime observations
- compute dynamic risk score
- emit one `DynamicAnalysisResult`

The dynamic layer should not:
- own batch orchestration
- own final verdict rules
- depend on family-specific malware heuristics in phase 1

### 33.2 Suggested Dynamic Subcomponents

Recommended internal split:
- `environment_manager`
- `sample_launcher`
- `event_collector`
- `event_normalizer`
- `score_calculator`
- `summary_builder`

`environment_manager`
- handles VM/sandbox readiness, reset, snapshot use

`sample_launcher`
- transfers or exposes sample and starts execution

`event_collector`
- gathers process and file events during observation window

`event_normalizer`
- maps collector-specific output into normalized event vocabulary

`score_calculator`
- computes `process_score`, `file_score`, and final `risk_score`

`summary_builder`
- creates concise dynamic behavior summary

### 33.3 Suggested Dynamic Pipeline

```text
run_dynamic_analysis(context):
  1. initialize empty DynamicAnalysisResult
  2. prepare VM or sandbox environment
  3. launch sample
  4. observe for configured time window
  5. collect raw process and file events
  6. normalize events and matched features
  7. compute dynamic scores
  8. build dynamic summary
  9. update context.dynamic_analysis
```

### 33.4 Suggested Dynamic Function Boundary Draft

- `initialize_dynamic_result()`
- `prepare_dynamic_environment(context)`
- `launch_sample(context)`
- `collect_process_events(context)`
- `collect_file_events(context)`
- `normalize_dynamic_events(raw_events)`
- `calculate_dynamic_score(normalized_events)`
- `build_dynamic_summary(normalized_events, scores)`
- `finalize_dynamic_result()`

Guidance:
- environment control should be isolated from event normalization
- process and file collection should remain separable
- scoring should consume only normalized evidence

### 33.5 Suggested Dynamic Raw Output Areas

Recommended raw buckets:
- `raw_environment_status`
- `raw_process_events`
- `raw_file_events`
- `raw_execution_log`

### 33.6 Suggested Dynamic Failure Behavior

- if VM fails to boot:
  - record `DYNAMIC_VM_BOOT_FAILURE`
  - emit error result
- if sample fails to launch:
  - record `DYNAMIC_SAMPLE_LAUNCH_FAILURE`
  - emit degraded dynamic result
- if event export is incomplete:
  - mark `status=partial`
  - preserve whatever events were captured
- if observation times out:
  - set `execution_status=timed_out`
  - continue to verdict stage

Recommended invariant:
- dynamic failures should still emit a structured `DynamicAnalysisResult` whenever the workflow reached the dynamic stage

### 33.7 Suggested Dynamic Output Invariant

At module completion:
- `executed=true`
- `execution_status` always populated
- `status in {ok, partial, error}`
- `matched_features` contains only normalized phase-1 dynamic feature names

## 34. Recorder And Batch Module Skeleton Draft

The recorder and batch layers should stabilize outputs and workflow scaling, not perform analysis logic.

### 34.1 Recorder Layer Responsibilities

- convert `AnalysisContext` into canonical JSON output
- determine result file paths and names
- write per-sample result files
- write batch summary files
- support schema validation or structural consistency checks

The recorder layer should not:
- compute evidence scores
- make analysis decisions
- reinterpret normalized evidence

### 34.2 Suggested Recorder Subcomponents

Recommended internal split:
- `path_resolver`
- `result_writer`
- `summary_writer`
- `schema_validator`

`path_resolver`
- generates deterministic result/log paths

`result_writer`
- writes per-sample canonical JSON

`summary_writer`
- aggregates and writes batch summary JSON

`schema_validator`
- checks result structure before or after persistence

### 34.3 Suggested Recorder Function Boundary Draft

- `resolve_result_path(context)`
- `resolve_log_path(context)`
- `validate_result_structure(context)`
- `write_single_result(context)`
- `write_batch_summary(summary_obj)`

Recommended invariant:
- recorder owns the final persisted shape, not intermediate modules

### 34.4 Batch Layer Responsibilities

- prepare sample lists
- deduplicate inputs
- assign `batch_id`
- run the single-sample workflow for each sample
- aggregate outcomes
- generate batch summary

The batch layer should not:
- duplicate analysis logic already defined in the single-sample path
- mutate per-sample evidence after workflow completion

### 34.5 Suggested Batch Subcomponents

Recommended internal split:
- `input_loader`
- `deduplicator`
- `workflow_dispatcher`
- `result_collector`
- `summary_aggregator`
- `rerun_controller`

`input_loader`
- reads directory or sample-list inputs

`deduplicator`
- removes duplicate `sha256` or path-equivalent inputs

`workflow_dispatcher`
- invokes the single-sample workflow repeatedly

`result_collector`
- gathers per-sample result paths and statuses

`summary_aggregator`
- computes batch-level counts, ratios, and artifact indexes

`rerun_controller`
- triggers one allowed auto-rerun for recoverable failures

### 34.6 Suggested Batch Pipeline

```text
run_batch(sample_list):
  1. load and normalize input list
  2. assign batch_id
  3. deduplicate samples
  4. run single-sample workflow for each sample
  5. apply one-step rerun policy where allowed
  6. collect result metadata
  7. build batch summary object
  8. write summary JSON
```

### 34.7 Suggested Batch Function Boundary Draft

- `load_batch_inputs(source)`
- `normalize_batch_inputs(raw_inputs)`
- `deduplicate_batch_inputs(inputs)`
- `dispatch_single_workflow(sample_path, batch_id)`
- `maybe_rerun_workflow(sample_result)`
- `collect_batch_results(result_objects)`
- `build_batch_summary(result_objects)`
- `write_batch_summary(summary_obj)`

### 34.8 Recorder And Batch Invariants

Recommended invariants:
- each processed sample yields at most one canonical final result JSON per workflow launch
- failed or degraded samples still appear in batch outputs
- batch summary never replaces per-sample result JSON as source of truth
- rerun metadata remains visible in both per-sample runtime data and batch summary

## 35. Verdict Module Skeleton Draft

The verdict layer should remain evidence-driven, simple, and fully normalized in phase 1.

### 35.1 Verdict Layer Responsibilities

- read normalized threat-intelligence, static, and dynamic evidence
- apply phase-1 verdict rules
- compute a stable final score
- emit one `VerdictResult`
- generate a short explanation and decision basis list

The verdict layer should not:
- parse raw VT responses
- parse raw static or dynamic tool outputs
- write result files directly

### 35.2 Suggested Verdict Subcomponents

Recommended internal split:
- `evidence_adapter`
- `signal_mapper`
- `rule_engine`
- `score_composer`
- `explanation_builder`

`evidence_adapter`
- reads normalized evidence from `AnalysisContext`

`signal_mapper`
- maps VT/static/dynamic values into `high / medium / low / unknown`

`rule_engine`
- applies the phase-1 three-class rules

`score_composer`
- computes `final_score`

`explanation_builder`
- builds `decision_basis` and `explanation`

### 35.3 Suggested Verdict Pipeline

```text
run_verdict(context):
  1. collect normalized evidence
  2. map evidence into phase-1 signals
  3. apply label rules
  4. compute final score
  5. build decision basis
  6. build explanation
  7. update context.verdict
```

### 35.4 Suggested Verdict Function Boundary Draft

- `collect_evidence(context)`
- `map_verdict_signals(evidence)`
- `apply_verdict_rules(signals)`
- `compose_final_score(signals, raw_scores)`
- `build_decision_basis(evidence, signals)`
- `build_verdict_explanation(label, basis)`
- `finalize_verdict_result()`

### 35.5 Suggested Verdict Invariants

At module completion:
- `final_label` is always one of:
  - `malicious`
  - `suspicious`
  - `benign`
- `final_score` is numeric in `[0,1]`
- `decision_basis` is never empty
- `explanation` is short, evidence-based, and readable

### 35.6 Suggested Verdict Failure Behavior

If evidence is incomplete:
- still emit a verdict
- prefer `suspicious` for heavily degraded evidence
- mention missing evidence explicitly in `decision_basis`

If verdict composition itself fails unexpectedly:
- set workflow status to degraded
- emit `VERDICT_INSUFFICIENT_EVIDENCE` if applicable

## 36. CLI Module Skeleton Draft

The CLI layer should stay thin and route user commands into the normalized workflow.

### 36.1 CLI Layer Responsibilities

- parse user commands and arguments
- load configuration
- dispatch into single-sample or batch workflows
- print compact human-readable progress or summary
- surface success and failure status cleanly

The CLI layer should not:
- contain analysis logic
- duplicate workflow rules
- mutate normalized result structures directly

### 36.2 Suggested CLI Subcomponents

Recommended internal split:
- `arg_parser`
- `config_loader`
- `command_dispatcher`
- `progress_reporter`
- `exit_status_mapper`

`arg_parser`
- parses command-line arguments

`config_loader`
- loads YAML config files and merges defaults

`command_dispatcher`
- routes to `single`, `batch`, `summary`, or `validate-result`

`progress_reporter`
- prints concise status updates

`exit_status_mapper`
- maps workflow outcomes to shell-friendly exit codes

### 36.3 Suggested CLI Commands

- `analyzer single --sample <path> --config <phase1-config>`
- `analyzer batch --input-dir <dir> --config <phase1-config>`
- `analyzer batch --sample-list <file> --config <phase1-config>`
- `analyzer summary --batch-id <batch-id> --results-dir <dir>`
- `analyzer validate-result --result <json-file>`

### 36.4 Suggested CLI Function Boundary Draft

- `parse_args(argv)`
- `load_runtime_config(args)`
- `dispatch_command(args, config)`
- `run_single_command(args, config)`
- `run_batch_command(args, config)`
- `run_summary_command(args, config)`
- `run_validate_result_command(args, config)`
- `map_exit_code(outcome)`

### 36.5 Suggested CLI Output Invariants

- command success should print the main artifact path or summary
- command failure should print a short actionable message
- batch mode should print `batch_id` and aggregate counts
- validation mode should print pass/fail with reason

## 37. Core, Config, And Models Relationship Draft

Phase 1 should keep `core`, `config`, and `models` clearly separated.

### 37.1 `core`

Purpose:
- shared workflow abstractions
- utility helpers
- shared enums and constants
- context lifecycle helpers

Suggested contents:
- workflow status enums
- error-code constants
- shared path helpers
- timestamp and ID helpers

### 37.2 `models`

Purpose:
- define canonical structured objects used across the workflow

Suggested model set:
- `AnalysisContext`
- `SampleInfo`
- `ThreatIntelResult`
- `AgentTraceItem`
- `StaticAnalysisResult`
- `DynamicAnalysisResult`
- `VerdictResult`
- `WorkflowRuntime`
- `WorkflowStatus`
- `BatchSummary`

Recommended rule:
- all cross-module payloads should be represented by models, not ad hoc dictionaries where avoidable

### 37.3 `config`

Purpose:
- define runtime-tunable behavior without changing code

Suggested config areas:
- phase-level defaults
- VT query behavior
- static thresholds and tool toggles
- dynamic environment parameters
- logging policy

Recommended rule:
- config values influence module behavior, but do not replace normalized models

### 37.4 Relationship Between Them

Recommended relationship:
- `config` provides parameter values
- `core` provides shared execution helpers and constants
- `models` define the structured data being passed around

In practical terms:
- modules read `config`
- modules use helpers from `core`
- modules consume and update `models`

### 37.5 Dependency Direction Draft

Recommended dependency direction:

```text
cli / batch / agent / static / dynamic / verdict / recorder
    -> core
    -> models
    -> config
```

And avoid:

```text
models -> analysis modules
config -> analysis modules with embedded logic
```

Meaning:
- models should stay passive
- config should stay declarative
- workflow logic lives in the analysis and orchestration modules

### 37.6 Suggested Invariants

- `models` do not call tools
- `config` does not encode procedural logic
- `core` does not depend on concrete tool outputs where avoidable
- business logic stays outside the canonical model definitions

## 38. Pre-Implementation Final Checklist

Before phase-1 coding starts, the following items should be explicitly confirmed.

### 38.1 Scope Confirmation

- phase target remains `phase_1_full_workflow_validation`
- no early termination rule still applies
- final labels remain:
  - `malicious`
  - `suspicious`
  - `benign`
- result format remains canonical JSON

### 38.2 Workflow Confirmation

- single-sample path is implemented first
- batch mode is a wrapper over the single-sample workflow
- VT stays as the first evidence entry point
- static analysis runs before dynamic analysis in the default phase-1 path

### 38.3 Tooling Confirmation

- threat-intel source for phase 1
- static tool set for phase 1
- dynamic environment choice for phase 1
- event collection capability for dynamic phase

### 38.4 Configuration Confirmation

- config file layout is accepted
- secrets will be injected through environment variables
- thresholds are configurable rather than hardcoded
- output directories are accepted

### 38.5 Output Confirmation

- per-sample JSON shape is accepted
- batch summary JSON shape is accepted
- log format and log level policy are accepted
- file naming rules are accepted

### 38.6 Testing Confirmation

- minimum schema validation exists
- at least one degraded-path test is planned
- single-sample success path test is planned
- small-batch summary validation is planned

### 38.7 Collaboration Confirmation

- the user confirms implementation may begin
- any unresolved environment-specific decision is either fixed or consciously deferred

## 39. Phase-1 MVP Definition

The phase-1 MVP should be the smallest end-to-end system that proves the workflow is viable.

### 39.1 MVP Goal

Produce one complete per-sample JSON result for one VT-confirmed malicious sample through the full phase-1 path.

### 39.2 MVP Required Capabilities

- ingest one PE sample
- calculate hashes
- query and normalize VT
- generate Agent decision #1
- run minimal static analysis
- generate Agent decision #2
- run minimal dynamic analysis
- compute final verdict
- write one canonical JSON result

### 39.3 MVP Minimal Static Capability

- parse PE structure
- extract strings
- detect basic packing/obfuscation signals
- compute normalized static score

### 39.4 MVP Minimal Dynamic Capability

- execute sample in isolated environment
- collect basic process events
- collect basic file events
- compute normalized dynamic score

### 39.5 MVP Minimal Traceability Requirement

The MVP is not complete unless it records:
- `agent_trace`
- `threat_intel`
- `static_analysis`
- `dynamic_analysis`
- `verdict`
- `runtime`

### 39.6 MVP Non-Goals

The phase-1 MVP does not need:
- optimized detection accuracy
- full ransomware family coverage
- advanced network-behavior modeling
- complete sandbox automation beyond the minimum run path
- large-scale batch optimization

### 39.7 MVP Completion Rule

The MVP is achieved when:
- one real sample completes the full workflow
- one canonical JSON result is produced
- the result is structurally valid
- the process is reproducible for a second run

## 40. Module Landing Order Before Coding

Phase 1 should be implemented in a sequence that minimizes integration risk.

### 40.1 Recommended Landing Order

1. `models`
2. `core`
3. `config`
4. `recorder`
5. `ingest`
6. `intel`
7. `agent`
8. `static_analysis`
9. `verdict`
10. `dynamic_analysis`
11. `cli`
12. `batch`

### 40.2 Why This Order

- `models`, `core`, and `config` stabilize interfaces first
- `recorder` stabilizes the final artifact early
- `ingest` and `intel` provide the first real data path
- `agent` becomes useful once normalized evidence begins to exist
- `static_analysis` is easier to integrate before dynamic execution
- `verdict` can be validated on VT + static before dynamic is ready
- `dynamic_analysis` is added after the rest of the pipeline already works
- `cli` and `batch` should sit on top of the stable pipeline

### 40.3 Recommended Validation Checkpoint After Each Landing

After each module landing:
- confirm interface shape still matches plan
- confirm result schema remains stable
- confirm logs remain readable
- confirm failures remain normalized

### 40.4 First Practical Coding Slice

Recommended first coding slice:
- `models`
- `core`
- `config`
- `recorder`

Reason:
- this slice creates the workflow skeleton without committing to heavy tool integration yet

### 40.5 Second Practical Coding Slice

Recommended second slice:
- `ingest`
- `intel`
- `agent`

Reason:
- this is the smallest meaningful evidence path after the output skeleton exists

### 40.6 Third Practical Coding Slice

Recommended third slice:
- `static_analysis`
- `verdict`

Reason:
- this allows an early end-to-end but partially simplified pipeline before dynamic execution arrives

### 40.7 Fourth Practical Coding Slice

Recommended fourth slice:
- `dynamic_analysis`
- `cli`
- `batch`

Reason:
- dynamic execution and scaling concerns should be integrated after the core path is already stable

## 41. Pre-Implementation Confirmation Summary

This section is the compact checkpoint to review immediately before coding starts.

### 41.1 Confirmed Phase-1 Intent

- research phase remains `phase_1_full_workflow_validation`
- primary purpose is full-path validation, not final accuracy optimization
- workflow remains:
  - `sample -> hash intelligence -> Agent -> static -> dynamic -> verdict -> JSON`
- no early termination remains in effect for phase 1

### 41.2 Confirmed Output Contract

- canonical per-sample JSON remains the source of truth
- final labels remain:
  - `malicious`
  - `suspicious`
  - `benign`
- `agent_trace` remains mandatory
- degraded workflows must still emit structured outputs

### 41.3 Confirmed Tooling Direction

- threat-intelligence starts with `VirusTotal`
- static analysis uses a minimal existing-tool strategy
- dynamic analysis uses isolated execution with minimal event collection
- batch mode remains secondary to the single-sample path

### 41.4 Confirmed Collaboration Rule

- implementation starts only after explicit user confirmation

## 42. First Coding Round Task Package

The first coding round should create the minimal structural foundation without committing yet to heavy tool integration.

### 42.1 Round-1 Objective

Create the workflow skeleton that can carry structured data end to end, even if some analysis sections are still placeholders.

### 42.2 Round-1 Scope

Recommended modules:
- `models`
- `core`
- `config`
- `recorder`

### 42.3 Round-1 Deliverables

- canonical model definitions
- workflow/runtime/status enums or constants
- config loader and default config wiring
- result path naming logic
- JSON result writer
- one empty or dummy workflow result write path for structural validation

### 42.4 Round-1 Success Criteria

- one synthetic or placeholder `AnalysisContext` can be persisted as valid JSON
- result file naming follows the agreed convention
- schema shape is stable enough for later modules to target

### 42.5 Round-1 Explicit Non-Goals

- no real VT integration yet
- no real static tool invocation yet
- no real dynamic execution yet
- no batch processing yet

## 43. Environment And Resource Preparation Checklist

Before implementation begins, the following environment and resource items should be ready or consciously deferred.

### 43.1 Local Development Prerequisites

- chosen implementation language/runtime
- package/dependency management approach
- writable output directories:
  - `results/`
  - `logs/`
  - `staging/`
- environment variable strategy for secrets

### 43.2 Threat-Intel Prerequisites

- `VirusTotal` API key
- API key injected through environment variable
- expected rate-limit behavior understood

### 43.3 Static-Analysis Prerequisites

- availability of `pefile`
- availability of `strings`
- availability of `DIE` or equivalent packer detector
- sample set organization under project directories

### 43.4 Dynamic-Analysis Prerequisites

- Windows VM or equivalent isolated execution environment
- snapshot/rollback capability
- sample delivery method into VM
- event collection method for:
  - process events
  - file events

### 43.5 Validation Resources

- at least one VT-confirmed malicious sample for single-sample workflow validation
- a small malicious subset for later batch validation
- a small benign subset for initial false-positive observation

### 43.6 Operational Safety Resources

- isolated execution policy for malware handling
- reset procedure after dynamic execution
- clear separation between raw temporary artifacts and normalized outputs

## 44. Round-1 File-Level Breakdown Draft

Round 1 should create the smallest useful file structure for the workflow skeleton.

### 44.1 Recommended Round-1 Files

```text
src/
├── core/
│   ├── constants.py
│   ├── enums.py
│   ├── ids.py
│   ├── paths.py
│   └── time_utils.py
├── models/
│   ├── analysis_context.py
│   ├── sample_info.py
│   ├── threat_intel_result.py
│   ├── agent_trace_item.py
│   ├── static_result.py
│   ├── dynamic_result.py
│   ├── verdict_result.py
│   ├── workflow_runtime.py
│   ├── workflow_status.py
│   └── batch_summary.py
├── config/
│   ├── loader.py
│   ├── phase1_config.py
│   ├── vt_config.py
│   ├── static_config.py
│   ├── dynamic_config.py
│   └── logging_config.py
└── recorder/
    ├── path_resolver.py
    ├── result_writer.py
    ├── summary_writer.py
    └── validator.py
```

### 44.2 File Responsibility Draft

`core/constants.py`
- shared string constants
- default field names when useful

`core/enums.py`
- workflow status enums
- stage enums
- label enums

`core/ids.py`
- `workflow_id`
- `batch_id`

`core/paths.py`
- resolve output, log, and staging paths

`core/time_utils.py`
- timestamp formatting helpers
- duration helpers

`models/*.py`
- one canonical model per file where practical

`config/loader.py`
- load YAML
- merge defaults
- expose one normalized runtime config object

`recorder/path_resolver.py`
- build per-sample and batch output paths

`recorder/result_writer.py`
- write canonical single-sample JSON

`recorder/summary_writer.py`
- write batch summary JSON

`recorder/validator.py`
- lightweight structural validation for result objects

### 44.3 Round-1 File Principles

- keep file names aligned with domain responsibilities
- avoid putting tool-specific logic into round-1 files
- keep recorder independent from analysis modules

## 45. Round-1 Interface Signature Draft

Round 1 should stabilize interfaces before real tool integration begins.

### 45.1 Core Utility Signatures

Suggested draft signatures:

```text
generate_workflow_id() -> str
generate_batch_id() -> str
now_iso() -> str
format_duration(start_time, end_time) -> float
resolve_result_path(workflow_id, sha256_prefix, mode) -> str
resolve_summary_path(batch_id) -> str
```

### 45.2 Model Initialization Signatures

Suggested draft signatures:

```text
create_empty_analysis_context(sample_path: str) -> AnalysisContext
create_default_runtime(phase_name: str) -> WorkflowRuntime
create_default_workflow_status() -> WorkflowStatus
```

### 45.3 Config Signatures

Suggested draft signatures:

```text
load_phase1_config(config_dir: str) -> Phase1Config
load_vt_config(config_dir: str) -> VTConfig
load_static_config(config_dir: str) -> StaticConfig
load_dynamic_config(config_dir: str) -> DynamicConfig
load_logging_config(config_dir: str) -> LoggingConfig
load_runtime_config(config_dir: str) -> RuntimeConfigBundle
```

### 45.4 Recorder Signatures

Suggested draft signatures:

```text
validate_analysis_context(context: AnalysisContext) -> ValidationResult
write_single_result(context: AnalysisContext, output_dir: str) -> str
write_batch_summary(summary: BatchSummary, output_dir: str) -> str
build_result_filename(workflow_id: str, sha256_prefix: str, mode: str) -> str
build_summary_filename(batch_id: str) -> str
```

### 45.5 Workflow Skeleton Signatures

Even before implementation, keep these top-level entry signatures stable:

```text
initialize_context(sample_path: str, phase_name: str) -> AnalysisContext
finalize_context(context: AnalysisContext) -> AnalysisContext
single_sample_workflow(sample_path: str, runtime_config: RuntimeConfigBundle) -> AnalysisContext
batch_workflow(sample_paths: list[str], runtime_config: RuntimeConfigBundle) -> BatchSummary
```

### 45.6 Signature Principles

- pass canonical models, not fragmented parameter lists, once workflow code grows
- keep return values explicit
- avoid hidden global state
- prefer a single config bundle at workflow entry points

## 46. Pre-Coding Final Confirmation Page

This is the final gate that should be reviewed with the user immediately before coding begins.

### 46.1 Must-Confirm Items

- implementation language/runtime
- first-round file layout acceptance
- first-round interface acceptance
- config directory acceptance
- output directory acceptance
- VT credential strategy acceptance
- dynamic environment availability or conscious deferral

### 46.2 Should-Confirm Items

- one sample chosen for MVP validation
- one batch naming strategy accepted
- one log verbosity policy accepted
- one result-validation approach accepted

### 46.3 Can-Defer Items

- batch performance optimization
- advanced dynamic behavior expansion
- family-specific feature enrichment
- phase-2 design choices

### 46.4 Coding Start Rule

Coding should start only when:
- no blocking ambiguity remains for round-1 files
- the user explicitly authorizes implementation
- the first coding slice is agreed to be:
  - `models`
  - `core`
  - `config`
  - `recorder`

### 46.5 Recommended Confirmation Prompt

Recommended pre-coding confirmation wording:

```text
Phase-1 planning is sufficiently detailed for round-1 implementation.
Round 1 will create the workflow skeleton only:
- models
- core
- config
- recorder

It will not yet integrate VT, static tools, dynamic execution, or batch logic.
Confirm whether I should start implementing this first slice.
```

## 47. Round-1 Interface And Model Refinement

Round 1 should refine interfaces just enough to prevent ambiguity during the first implementation slice.

### 47.1 `AnalysisContext` Minimal Required Fields

Recommended round-1 minimum:
- `sample`
- `threat_intel`
- `agent_trace`
- `static_analysis`
- `dynamic_analysis`
- `verdict`
- `runtime`
- `workflow_status`

Recommended round-1 rule:
- all fields exist from initialization time, even if many are placeholders

### 47.2 `WorkflowStatus` Minimal Required Fields

Recommended minimum:
- `status`
- `fatal`
- `error_code`
- `message`

Suggested default initialization:
- `status = "completed_degraded"` only after later downgrade logic
- initial default should be neutral or workflow-start state as defined in implementation

### 47.3 `WorkflowRuntime` Minimal Required Fields

Recommended minimum:
- `workflow_id`
- `batch_id`
- `start_time`
- `end_time`
- `duration_sec`
- `phase`
- `rerun_count`
- `final_attempt`
- `notes`

### 47.4 `ValidationResult` Draft

Recommended shape:

```text
ValidationResult
- valid: bool
- errors: list[str]
- warnings: list[str]
```

Purpose:
- allow recorder validation without mixing schema checks into unrelated modules

### 47.5 `RuntimeConfigBundle` Draft

Recommended shape:

```text
RuntimeConfigBundle
- phase1
- virustotal
- static_analysis
- dynamic_analysis
- logging
```

Purpose:
- provide one top-level config object at workflow entry points

### 47.6 Round-1 Interface Refinement Rules

- avoid optional return types when a canonical model can be returned with defaults
- prefer one explicit result object over many loosely related primitives
- keep recorder interfaces file-system focused, not analysis focused

## 48. Local Environment Readiness Checklist

This checklist is for the local machine before round-1 or later slices begin.

### 48.1 Basic Project Directories

Confirm these paths exist or can be created:
- `results/`
- `logs/`
- `staging/`
- `configs/`
- `src/`

### 48.2 Language And Runtime

Confirm:
- chosen implementation language
- package manager choice
- virtual environment or isolated dependency strategy

### 48.3 Threat-Intel Readiness

Confirm:
- `VT_API_KEY` is obtainable
- environment-variable injection approach is available
- outbound network policy for VT queries is acceptable when implementation starts

### 48.4 Static-Tool Readiness

Confirm:
- `pefile` can be installed or is already available
- `strings` exists or an equivalent is available
- `DIE` is available now or consciously deferred

### 48.5 Dynamic-Environment Readiness

Confirm:
- Windows VM exists or can be prepared
- snapshot/rollback is supported
- one-sample execution method is known
- one basic process/file event collection method is known

### 48.6 Sample Readiness

Confirm:
- one VT-confirmed malicious sample is selected for MVP
- a small malicious subset is available for later batch checks
- a small benign subset is available or consciously deferred

### 48.7 Safety Readiness

Confirm:
- malware execution will remain isolated
- reset procedure exists after each dynamic run
- no production or sensitive host environment will be used for unsafe execution

### 48.8 Round-1 Readiness Rule

Round 1 may still begin even if dynamic-environment items are not fully ready, because round 1 does not yet implement dynamic execution.

## 49. Local Environment Step-By-Step Check

This section converts the readiness checklist into an explicit pre-coding review sequence.

### 49.1 Project Structure Check

Confirm:
- project root is stable
- `project-memory/` exists
- `results/`, `logs/`, `staging/`, `configs/`, and `src/` can be created or are already present

### 49.2 Runtime Tooling Check

Confirm:
- implementation language choice is known
- package/dependency manager choice is known
- isolated dependency strategy is available

### 49.3 VT Readiness Check

Confirm:
- `VT_API_KEY` can be provided later
- environment-variable loading approach is acceptable
- network access policy for VT is understood

### 49.4 Static Tooling Check

Confirm:
- `pefile` can be installed later
- `strings` is available or a substitute exists
- `DIE` is available now or consciously deferred

### 49.5 Dynamic Readiness Check

Confirm:
- Windows VM plan exists
- snapshot/rollback method exists
- basic process/file event collection plan exists

### 49.6 Sample Check

Confirm:
- one VT-confirmed malicious sample can be nominated for MVP
- a small malicious subset exists
- a small benign subset exists or is consciously delayed

## 50. Core Object Refinement Notes

This section sharpens the three most important round-1 structural objects.

### 50.1 `AnalysisContext` Refinement

Recommended round-1 shape:

```text
AnalysisContext
- sample: SampleInfo
- threat_intel: ThreatIntelResult
- agent_trace: list[AgentTraceItem]
- static_analysis: StaticAnalysisResult
- dynamic_analysis: DynamicAnalysisResult
- verdict: VerdictResult
- runtime: WorkflowRuntime
- workflow_status: WorkflowStatus
```

Refinement rules:
- initialize every field eagerly
- avoid `null` top-level sections where defaults can exist
- treat this object as the only canonical per-sample workflow container

### 50.2 `RuntimeConfigBundle` Refinement

Recommended round-1 shape:

```text
RuntimeConfigBundle
- phase1: Phase1Config
- virustotal: VTConfig
- static_analysis: StaticConfig
- dynamic_analysis: DynamicConfig
- logging: LoggingConfig
```

Refinement rules:
- workflow entry points should receive one bundle rather than many config fragments
- module internals may read only the config subsection they need

### 50.3 `ValidationResult` Refinement

Recommended round-1 shape:

```text
ValidationResult
- valid: bool
- errors: list[str]
- warnings: list[str]
```

Refinement rules:
- schema validation should never silently fail
- warnings should be non-blocking
- errors should block result persistence only if the output is structurally unusable

## 51. Final Pre-Coding Questionnaire

This is the last planning checkpoint before implementation begins.

### 51.1 Must-Answer Questions

1. What implementation language/runtime will be used?
2. Is the round-1 file layout accepted?
3. Are the round-1 interfaces accepted?
4. Is the config-directory approach accepted?
5. Is the result/log/staging directory plan accepted?
6. Will VT credentials be injected through environment variables?

### 51.2 Should-Answer Questions

1. Which sample is the MVP validation sample?
2. Is `DIE` required in phase 1 or allowed to be deferred if inconvenient?
3. Is the initial log verbosity policy acceptable?
4. Is one degraded-path validation scenario already identified?

### 51.3 Can-Defer Questions

1. Exact batch size after MVP
2. Dynamic-environment expansion details
3. Phase-2 architecture choices

### 51.4 Start Rule

Implementation should begin only when:
- must-answer questions are resolved enough for round 1
- no blocking disagreement remains on the first coding slice
- the user explicitly authorizes coding

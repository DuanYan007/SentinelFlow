# Decision Log

## Confirmed Decisions

### Research Direction
- Focus on:
  - detection effectiveness
  - Agent value

### Data
- Real self-collected ransomware samples
- Approximate scale: `300+`
- Add a small benign set in the first version to observe false positives

### First Version Workflow
- Minimal closed loop first
- `Hash intelligence -> Agent -> static or dynamic -> three-class output`
- If VT is insufficient, Agent decides static or dynamic
- If static is uncertain, add one dynamic analysis pass
- In phase 1, do not rely on early termination; prioritize exercising the full workflow

### Agent
- `LLM + rules + skill/tool calling`
- Decision basis:
  - rules + scoring
- LLM role:
  - decision
  - orchestration
  - explanation

### Static Analysis
- No PE execution
- Existing tools first
- Minimal first version with key signals only
- Signals:
  - PE structure
  - suspicious imports/APIs
  - strings/config traces

### Dynamic Analysis
- Execute only in sandbox/VM
- Existing tools first
- Minimal first version with key behaviors only
- Signals:
  - file behavior
  - encryption-related behavior
  - destructive/system-impact behavior

### Evaluation
- Main validation target:
  - whether Agent/skill-driven automation is better than fixed workflows
- Baselines:
  - `hash -> static -> dynamic -> verdict`
  - `hash -> static -> verdict`
  - `hash -> dynamic -> verdict`

### Phase-2 Direction
- Tentative priorities:
  - strengthen Agent capability
  - expand batch experimentation
- Final phase-2 decision remains open until phase 1 finishes

### Output
- Final classes:
  - `malicious`
  - `suspicious`
  - `benign`
- Persist results as `JSON`
- Include:
  - sample metadata
  - Agent path and reasons
  - VT/static/dynamic evidence
  - static/dynamic scores
  - matched features
  - invoked skills/tools

### Execution Strategy
- Progression:
  - `single sample -> small batch -> full batch`
- Single-sample closed loop:
  - choose a sample with clear malicious VT verdict
- Small-batch closed loop:
  - start with VT high-confidence malicious samples
  - add a small benign set for initial false-positive observation

### Tooling Direction
- Static analysis:
  - existing multi-tool combination
  - minimum viable set to be chosen later
- Dynamic analysis:
  - minimum viable tooling to be chosen later
- Dynamic target environment:
  - minimum viable choice to be selected later

### Environment Decisions
- Prefer `uv` and a project-local virtual environment for dependency isolation
- Current host environment is Ubuntu 24.04
- VT credentials are currently stored in an ignored local secret file under `configs/secrets/`
- Static tool preparation status:
  - `pefile` installed in `.venv`
  - `strings` available from system binutils
  - `DIE` downloaded and extracted locally under `tools/bin/`

### Round-1 Implementation Status
- Round-1 skeleton coding has started
- Implemented modules:
  - `models`
  - `core`
  - `config`
  - `recorder`
- Added a placeholder `single_sample_workflow` skeleton that can emit canonical JSON

### Round-2 Implementation Status
- Implemented modules:
  - `ingest`
  - `intel`
  - `agent`
- Added local YAML config files under `configs/`
- Workflow now:
  - computes `md5 / sha1 / sha256`
  - reads local VT config
  - supports optional VT querying
  - records rule-based agent trace items

### Round-3 Implementation Status
- Implemented modules:
  - `static_analysis`
  - `verdict`
- Workflow now:
  - runs `pefile`-based PE parsing
  - extracts strings with system `strings`
  - normalizes static features
  - computes heuristic static risk scores
  - emits a non-placeholder verdict based on VT/static evidence

### Round-4 Implementation Status
- Implemented modules:
  - `dynamic_analysis`
  - `batch`
- Dynamic analysis is safe-by-default:
  - does not execute samples on the host
  - remains disabled unless config enables an event-log adapter
- Batch runner now:
  - filters non-file inputs
  - processes file samples through the single-sample workflow
  - writes per-sample JSON
  - writes batch summary JSON
- VT querying has been validated with the local secret config.

### CLI Implementation Status
- Implemented initial CLI module:
  - `cli`
- Added command:
  - `validate-result`
- Added command:
  - `single`
- Current CLI behavior:
  - reads a result JSON file
  - validates canonical phase-1 result structure
  - returns non-zero for missing files, invalid JSON, or structural validation errors
  - runs one sample through the existing phase-1 workflow
  - writes one canonical result JSON to the configured output directory
- Validation status:
  - Python syntax check passed for `src/cli/*.py` and `src/recorder/validator.py`
  - `validate-result` returned `OK` for an existing VT-enabled single-sample result JSON
  - `single` completed successfully on one real PE sample
  - the generated result JSON also passed `validate-result`

### Static Analysis V2 Modeling Status
- Added the first v2 static-analysis model file:
  - `src/models/static_analysis_v2.py`
- The initial v2 model now defines:
  - schema versioning
  - mixed `tool_outputs` container
  - `raw_evidence` items and `evidence_ref` references
  - normalized `pe_basic / section_features / import_features`
  - module/rule score breakdown containers
  - top-level summary container
- Current scope:
  - data-structure only
  - no extractor/rule/scoring integration yet
- Validation status:
  - Python syntax check passed
  - default object creation and `to_dict()` serialization passed

### Static Analysis V2 Extractor Status
- Added the first extractor module:
  - `src/static_analysis/pefile_extractor.py`
- Current extractor scope:
  - parses PE headers via `pefile`
  - emits v2 `tool_outputs.pefile`
  - emits key `raw_evidence`
  - fills initial normalized:
    - `pe_basic`
    - `section_features`
    - `import_features` as temporary `unclassified`
- Validation status on one real PE sample:
  - syntax check passed
  - extractor returned `status=ok`
  - extracted `11` sections
  - extracted `142` imports
  - produced `13` raw-evidence records
- Remaining v2 static-analysis work:
  - rule loader
  - rule matching
  - scoring integration
  - workflow integration

### Static Analysis V2 Rule Data Status
- Added rule-data files:
  - `configs/rules/static-section-rules.yaml`
  - `configs/rules/static-import-rules.yaml`
- Section-rule file currently defines:
  - `version / enabled / defaults / categories / rules / extensions`
  - `5` categories
  - `5` rules
- Import-rule file currently defines:
  - `version / enabled / defaults / categories / rules / extensions`
  - `8` categories
  - `8` rules
- Validation status:
  - both YAML files loaded successfully via local `PyYAML`
- Remaining work after rule-data creation:
  - apply rules to v2 extractor outputs
  - feed rule hits into normalized features and scoring

### Static Analysis V2 Rule Loader Status
- Added loader module:
  - `src/static_analysis/rule_loader.py`
- Current loader scope:
  - loads one rule set from YAML
  - validates root shape and required fields
  - validates category existence for each rule
  - returns a `StaticRuleBundle` for section/import rule sets
- Validation status:
  - syntax check passed
  - loaded `static-section-rules.v1` with `5` categories and `5` rules
  - loaded `static-import-rules.v1` with `8` categories and `8` rules
- Remaining v2 static-analysis work after loader:
  - extractor integration
  - scoring integration
  - workflow integration

### Static Analysis V2 Rule Matcher Status
- Added matcher module:
  - `src/static_analysis/rule_matcher.py`
- Current matcher scope:
  - supports scalar section-style conditions
  - supports `any_of`
  - supports `threshold_ref / values_ref / combos_ref`
  - supports import-style `dlls/apis` exact and prefix matching
- Validation status on one real PE sample:
  - syntax check passed
  - section matches: `3`
  - import matches: `8`
  - observed import categories:
    - `filesystem`
    - `process`
    - `registry`
    - `service`
- Remaining v2 static-analysis work after matcher:
  - populate normalized categorized import/section features
  - scoring integration
  - workflow integration

### Static Analysis V2 Extractor Integration Status
- Updated `src/static_analysis/pefile_extractor.py` to apply both rule sets during extraction.
- Current integrated behavior:
  - section rule hits are converted into `raw_evidence`
  - import rule hits write back:
    - `category`
    - `matched_rule_id`
    - `risk_weight`
    - `evidence_ref`
  - normalized import features now aggregate by category
  - top-level and tool-level summaries now include rule-hit key events
- Validation status on one real PE sample:
  - extractor returned `status=ok`
  - categorized import groups observed:
    - `filesystem`
    - `process`
    - `registry`
    - `service`
  - example import write-back confirmed:
    - `FindNextFileW -> filesystem / IMP-FS-001`
    - `WriteFile -> filesystem / IMP-FS-001`
- Remaining v2 static-analysis work after extractor integration:
  - workflow integration
  - batch/CLI level integration validation

### Static Analysis V2 Service Integration Status
- Added config fields in `src/config/static_config.py` and `configs/static-analysis.yaml`:
  - `enable_v2_output`
  - `rules_dir`
  - `section_rules_file`
  - `import_rules_file`
- Added a v1-compatible extension field in `src/models/static_result.py`:
  - `v2`
- Added v2 score-breakdown generation in `src/static_analysis/pefile_extractor.py`:
  - module-level contributions
  - rule-level contributions
  - normalization strategy metadata
- Integrated v2 execution into `src/static_analysis/service.py`:
  - keep v1 output unchanged for downstream verdict logic
  - attach v2 output as parallel structured data
- Expanded import-rule coverage with additional APIs:
  - registry open-key APIs
  - service open-service APIs
  - `urlmon.dll` network tool coverage
- Validation status on one real PE sample:
  - syntax checks passed
  - v1 static-analysis status remained `ok`
  - v1 static score remained `0.17`
  - v2 output attached successfully
  - v2 static score observed: `0.401`
  - v2 categorized imports observed:
    - `filesystem`
    - `process`
    - `registry`
    - `service`
  - v2 rule-score item count observed: `7`

### Workflow / CLI / Agent V2 Integration Status
- Extended `src/recorder/validator.py`:
  - validates the presence and basic shape of `static_analysis.v2`
- Extended `src/cli/main.py`:
  - `single` now validates the generated JSON before returning success
  - `single` prints `STATIC_V2 <score>` when v2 is present
- Extended `src/agent/service.py`:
  - the static-analysis stage now reads v2 experimental signals
  - emits a v2-based suggestion field in `agent_trace`
- Validation status on one real single-sample run:
  - result file created:
    - `results/wf-20260501T072733Z-992d03b2__fe81c5caa0e2__single.json`
  - CLI output included:
    - `STATIC_V2 0.401`
  - explicit `validate-result` returned `OK`
  - `agent_trace` recorded:
    - `static_v2_risk_score=0.401`
    - import categories `filesystem/process/registry/service`
    - suggested action `collect_more_static_and_dynamic_evidence`

### Static Analysis V2 Multi-Tool Status
- Extended `src/static_analysis/pefile_extractor.py` with `strings` integration:
  - stores strings tool output in `tool_outputs.strings`
  - records keyword-hit evidence into `raw_evidence`
  - adds string-based key hits into v2 summary
- Extended `src/static_analysis/pefile_extractor.py` with best-effort `DIE` integration:
  - runs local DIE binary with a 5-second timeout
  - records `partial/error/skipped` status instead of blocking the chain
  - stores stdout/stderr snippets when available
- Validation status on one real PE sample:
  - extractor status remained `ok`
  - `strings` status: `ok`
  - `strings` summary: `strings_ok count=3531 matched_categories=ransom_note`
  - `die` status: `partial`
  - `die` summary: `die execution timed out`
  - v2 raw-evidence count observed: `26`
- Practical conclusion:
  - `strings` is now a stable v2 source
  - current local `DIE` CLI is not yet a stable fast source in this environment and needs later refinement

### Full Static-Only Experiment Status
- Added a dedicated static-only batch runner:
  - `src/batch/static_experiment.py`
- Scope of the experiment:
  - ingest
  - static analysis only
  - no VT
  - no Agent
  - no dynamic execution
  - no verdict generation
- Executed corpus-scale run results:
  - batch id: `static-batch-20260501T074257Z-c91307`
  - total directory entries: `170`
  - processed file samples: `169`
  - skipped non-file entries: `1`
  - static status counts:
    - `ok=168`
    - `error=1`
  - v2 present count: `168`
  - mean v2 risk score: `0.294`
- Persisted artifact locations:
  - result directory:
    - `results/static-experiments/static-batch-20260501T074257Z-c91307`
  - summary:
    - `results/static-experiments/summaries/static-batch-20260501T074257Z-c91307__summary.json`
- Added documentation artifacts:
  - `docs/static-analysis-experiment-record.md`
  - `docs/static-analysis-single-sample-trace.md`

### Collaboration Rule
- Confirm with the user before writing implementation code
- Keep planning interaction concise and option-based
- Maintain a project-root rules file for memory-first startup behavior

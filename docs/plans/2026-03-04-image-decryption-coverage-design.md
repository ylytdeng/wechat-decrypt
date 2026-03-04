# Image Decryption Coverage Design

> Date: 2026-03-04  
> Status: Approved (all design sections confirmed)

## 1. Problem Statement

The project has already decrypted a large number of images, but there is still a long tail of historical images that remain unresolved after multiple rounds. The current workflow relies on manual browsing + memory scanning, which works, but is not yet run as a measurable, repeatable coverage pipeline.

The target for this design is maximum historical coverage (not only recent images), with a process that can run for many rounds and keep producing measurable progress.

## 2. Goals and Non-Goals

### Goals

1. Build a repeatable round-based workflow that continuously reduces unresolved images.
2. Maximize conversion of user manual effort (opening images in WeChat) into actual key capture and decryption gain.
3. Produce per-round evidence and reports so progress is auditable and strategy can be adjusted.
4. Reach a practical near-full-coverage state for historical images.

### Non-Goals

1. Do not require one-shot completion in a single run.
2. Do not block progress on deep reverse-engineering before process optimization.
3. Do not introduce broad refactors outside image decryption coverage workflow.

## 3. High-Level Strategy

Use a deterministic six-step loop per round:

1. Baseline: quantify unresolved set by source/month/type.
2. Target Plan: generate next opening task list (prioritized by expected yield).
3. Capture: run key scanner while manually opening targeted images in WeChat.
4. Rebuild: run decryption using updated key mappings.
5. Evaluate: compare before/after metrics for this round.
6. Next Round: pick the next target set based on residual concentration.

This turns ad-hoc retries into a closed-loop pipeline with explicit inputs, outputs, and stop conditions.

## 4. Architecture and Data Flow

### 4.1 Round Workspace

Create one artifact directory per round under:

`work/image_coverage/round-YYYYMMDD-HHMM/`

Each round stores:

1. Input snapshots (`config.json`, `image_keys.json`, unresolved summary before run)
2. Planned tasks (`open_tasks.md`)
3. Execution outputs (scanner delta, decrypt summary)
4. Final report (`report.md`)

### 4.2 Components

1. `analyze_unresolved`
   - Reads decrypted outputs and local DB mapping.
   - Produces unresolved distribution by chat/hash/month/type.
2. `generate_open_tasks`
   - Converts top unresolved buckets into an actionable open-image checklist.
3. `capture_keys`
   - Runs continuous scanner and records new key mappings for this round.
4. `run_decrypt`
   - Runs decrypt pass against updated mappings.
5. `round_report`
   - Computes gain and residual hotspots and proposes next round targets.

### 4.3 Data Flow

`analyze_unresolved -> generate_open_tasks -> capture_keys -> run_decrypt -> round_report -> next round`

## 5. Guardrails and Error Handling

### 5.1 Hard Guardrails

1. Disable fallback single-key behavior in coverage rounds to prevent false-success artifacts.
2. Validate newly discovered keys before counting them as effective.
3. Reject rounds with missing snapshots (no reproducibility).
4. Alert on low-yield rounds (high manual time, low decryption gain).

### 5.2 Operational Safety

1. Record exact environment and paths at round start.
2. Run preflight checks: scanner availability, permissions, path accessibility.
3. Keep full round artifacts for rollback and audit.

## 6. Validation and Acceptance

### 6.1 Per-Round Validation

1. Required metrics:
   - newly decrypted count
   - unresolved/no-key reduction
   - effective new key count
2. Required artifact:
   - round report with complete metric fields

### 6.2 Quality Validation

1. Sample newly decrypted files for format validity (magic/header + openability checks).
2. If quality threshold fails, isolate suspect keys and rerun.

### 6.3 Stage Validation (every 5 rounds)

1. Compare unresolved reduction against baseline.
2. Verify whether top residual buckets are changing.
3. Track throughput: decrypted gain per hour of manual opening.

### 6.4 Final Acceptance (A-mode)

1. Residual unresolved ratio reaches agreed threshold (for example `<1%`) or absolute ceiling.
2. Three consecutive low-yield rounds trigger final long-tail assessment and closure decision.

## 7. Execution Playbook

Per round:

1. Run baseline analysis and snapshot inputs.
2. Generate and follow targeted open-image task list.
3. Capture keys during manual image browsing.
4. Rerun decrypt and produce round report.
5. Re-prioritize based on residual concentration.

## 8. Risks and Mitigations

1. Risk: long-tail sources produce very low key yield.
   - Mitigation: dynamic reprioritization with low-yield alerts and bucket rotation.
2. Risk: false-positive keys pollute mapping.
   - Mitigation: per-key validation before acceptance.
3. Risk: hidden environment/permission drift.
   - Mitigation: mandatory preflight and round snapshots.

## 9. Design Decision Summary

1. Chosen direction: semi-automated coverage loop as primary path.
2. Manual-only loop remains available as fallback.
3. Deep algorithmic reverse-engineering is deferred to non-blocking parallel exploration.

## 10. Approval Record

Approved by user in staged sections:

1. Architecture: confirmed.
2. Components and data flow: confirmed.
3. Guardrails and error handling: confirmed.
4. Validation and acceptance criteria: confirmed.

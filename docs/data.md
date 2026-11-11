# Data and analysis definitions

Each `data/<campaign>/records.json` file contains one row per planned first attempt. The files retain all 990 formal, 270 observer, and 360 diagnostic tasks. The formal allocation comprises 450 scale runs and 540 fault/control episodes. Every fault/control episode includes initial execution and prescribed restart. Restart phases and repeated samples are parts of the episode, not additional replications.

## Common fields

| Field | Meaning |
| --- | --- |
| `id` | Stable planned task identifier |
| `attempt` | First-attempt index, always 1 in these data |
| `session` | Fixed session number, 1–3 within each campaign |
| `block` | Matched block shared by the compared tools or profiles |
| `sequence` | Execution order within the frozen campaign schedule |
| `state` | Protocol execution state |
| `metrics` | Validated task observations in original units |

Metric names ending in `_ns` use nanoseconds and `_bytes` use bytes. CPU percent uses 100% for one core. Diagnostic `_ticks` metrics use 100 ticks per second. Formal idle memory values are time-weighted window means. Calibration memory values are endpoint readings. Metrics absent from a record remain missing; they are not replaced with zero.

## Formal records

`condition` retains the workload, switch count, fault, worker interpreter, configuration, build mode, and input identity needed to match the frozen design. `eligibility` contains initial and restart cleanup/timeout flags and the retained exclusion reason. `outcomes` contains protocol, native, readiness, and cleanup outcomes. The analysis recomputes the record exclusion and checks its stored value.

An ordinary-stop timeout or incomplete ordinary cleanup in either phase excludes the whole record from primary performance comparisons. A usable record can still lack an individual metric. Both members must supply the metric for a paired comparison. Outcome counts retain all planned records. There are 916 eligible formal records and 74 excluded records.

`process-birth.json` contains the derived kernel-tick intervals for all 450 scale runs. Absolute process identities are omitted. The adjacent-gap statistic is undefined for a one-switch run and is represented by null.

## Calibration records

Observer profiles are B (boundary validation), T (timestamps), and S (timestamps with periodic resource sampling). Diagnostic profiles are native, off, stages, and detail. Calibration campaigns retain their own harness versions and timing boundaries. Their costs are reported separately from the formal comparison.

## Statistical outputs

The main effect is the median within-block difference, with left minus right defined by `protocol/comparisons.json`. Conservative pointwise 95% rank intervals condition on three fixed sessions and observed complete-case session counts. Thirty pairs use ranks 10 and 21; fifteen pairs use ranks 4 and 12. Missing sessions or insufficient counts yield an unavailable interval with its reason. Completion intervals use the exact Clopper–Pearson calculation.

Supplementary fixed-session and hierarchical-session bootstrap intervals use 10,000 draws and master seed 20261029. Condition-derived seeds and canonical observation ordering reproduce the retained references.

`expected-comparisons.json` and `expected-outcomes.json` are comparison targets. The analysis calculates values from task observations before comparing them to these targets. `data/manifest.json` checks the published input bytes. The source content identities record provenance without local paths, process identifiers, or host inventories.

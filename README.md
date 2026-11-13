# p4net lifecycle evaluation artifacts

Data and offline analysis for **p4net: Lifecycle Management and Recovery for P4 Network Emulation**. The experiment compares p4net v1.8.0, P4-Utils, and a workflow assembled from official P4 tutorial components on one WSL2 host.

| Campaign | First-attempt tasks | Design |
| --- | ---: | --- |
| Formal scale and fault/control | 990 | Three tools, five scales or six fault/control conditions, three sessions |
| Observer calibration | 270 | Three tools, two scales, three observation profiles, three sessions |
| Diagnostic calibration | 360 | Three tools, two scales, four entry profiles, three sessions |

The offline workflow recomputes all 1,125 primary paired comparisons, ordinary cleanup outcomes, and the nine paper tables. It checks the results against the retained estimates. All planned outcomes remain in the data, including the 74 formal records excluded from primary performance comparisons.

## Reproduce the results

Use Python 3.10 or later from the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m lifecycle_artifacts reproduce --output results
```

The command writes `summary.json`, `comparisons.json`, `outcomes.json`, nine CSV tables, and a complete effect CSV under `results/`. It uses the distributed observations without starting network processes or requiring root.

To also recompute the two supplementary bootstrap references, each using 10,000 resamples:

```bash
python -m lifecycle_artifacts reproduce --bootstrap --output results
```

## Figures

```bash
python -m pip install -e '.[plots]'
python -m lifecycle_artifacts plot --results results --output results/figures
```

Plotting requires a locally installed Times New Roman font. If font discovery cannot find it, provide `--font path/to/Times_New_Roman.ttf`.

## Layout

- `data/`: per-task metrics, outcomes, process-birth intervals, and comparison targets.
- `protocol/`: allocation, measurement boundaries, eligibility rules, and comparison definitions.
- `src/lifecycle_artifacts/`: analysis, interval calculations, tables, and plotting.
- `docs/`: data schema, environment, and reproduction details.
- `tests/`: record coverage, numerical regression, and statistical edge cases.

`collection/` provides [fresh collection entry points](docs/collection.md), pinned worker requirements, and boundary-only native qualification. The offline analysis requires neither root nor the native toolchain. [The p4net SDK](https://github.com/zhh2001/p4net) remains in its own repository.

## Citation and license

Citation metadata is in `CITATION.cff`. A versioned archive DOI can be added after the reviewed release is archived.

Code and documentation use [Apache-2.0](LICENSE). The published observations, expected result data, and figures use [CC BY 4.0](DATA_LICENSE).

# Local validation

The initial offline workflow was checked on WSL2 with Python 3.10.20 and 3.12.3. Each interpreter passed 22 tests without failures or skips. The complete primary reproduction matched all 1,125 retained comparisons, including 814 available intervals and 311 unavailable intervals with their reasons.

Both 10,000-draw bootstrap references were recomputed for every comparison under Python 3.12 and matched the retained results. The tests additionally check one available reference comparison from each campaign under both interpreters.

Six data figures were rendered under both interpreters in PDF and PNG with Times New Roman. Both runs produced the same 162 median/IQR plotting summaries. The figure PDFs contain embedded font subsets.

Ruff, formatting, and mypy checks passed. Wheel and source distributions were built, installed into four independent environments, and used to reproduce the full primary comparison grid. Reproduction also passed using the data extracted from the source distribution. The workflow configuration passed actionlint.

The initial checks covered offline analysis, packaging, and rendering. The collection addition was checked locally on the same WSL2 host with Python 3.10.20 and 3.12.3. Each interpreter passed 712 tests and 704 subtests without failures or skips. Native qualification passed 24 checks as root with p4c and BMv2: six ordinary workflows and 18 diagnostic workflows at 1/16 switches. Ordinary cleanup was clean in every check. No new performance campaign was collected.

Run the available local checks with:

```bash
python -m pip install -e '.[dev,plots,collection-tests]'
ruff check .
ruff format --check .
mypy src/lifecycle_artifacts collection/collect.py collection/capture.py collection/formal_checks.py collection/runtime
pytest -q
python -m lifecycle_artifacts reproduce --bootstrap --output results
python -m lifecycle_artifacts plot --results results
python -m build
```

Collection engine tests use temporary synthetic records and subprocess fixtures.
They cover process identities, bounded event transport, interrupted publication,
gate reviews, and explicit retries. Native qualification runs separately using
the commands in [collection.md](collection.md).

# Local validation

The offline workflow was checked on WSL2 with Python 3.10.20 and 3.12.3. Each interpreter passed 22 tests without failures or skips. The complete primary reproduction matched all 1,125 retained comparisons, including 814 available intervals and 311 unavailable intervals with their reasons.

Both 10,000-draw bootstrap references were recomputed for every comparison under Python 3.12 and matched the retained results. The tests additionally check one available reference comparison from each campaign under both interpreters.

Six data figures were rendered under both interpreters in PDF and PNG with Times New Roman. Both runs produced the same 162 median/IQR plotting summaries. The figure PDFs contain embedded font subsets.

Ruff, formatting, and mypy checks passed. Wheel and source distributions were built, installed into four independent environments, and used to reproduce the full primary comparison grid. Reproduction also passed using the data extracted from the source distribution. The workflow configuration passed actionlint.

The checks cover offline analysis, packaging, and rendering. No new network workloads or resource sampling were run. Remote GitHub Actions runs begin after the repository content is pushed.

Run the available local checks with:

```bash
python -m pip install -e '.[dev,plots]'
ruff check .
ruff format --check .
mypy src/lifecycle_artifacts
pytest -q
python -m lifecycle_artifacts reproduce --bootstrap --output results
python -m lifecycle_artifacts plot --results results
python -m build
```

# Collect fresh observations

Collection uses Linux namespaces, root, p4c, BMv2, and three worker environments.
The recorded conditions are described in [environment.md](environment.md).
Fresh collection writes new journals under `results/`; distributed observations
remain in `data/`.

## Install the worker environments

Use Python 3.10.20 for all workers. The recorded native toolchain used p4c
1.2.5.10, `simple_switch_grpc` 1.15.0-2bdd0b7b, and Mininet 2.3.0-1.1.
The common launcher uses `/usr/bin/python3`, which was Python 3.12.3 in that
environment. Required commands are `p4c`, `p4c-bm2-ss`, `simple_switch_grpc`,
`mnexec`, `ip`, `ping`, `ethtool`, `sysctl`, `mount`, `unshare`, and `cpp`.
The launcher needs Linux pidfd support and mount permission.

Run the following from the repository root. `python3.10` denotes the selected
Python 3.10.20 interpreter. Keep the checkout and setup directory on the Linux
filesystem, on the same filesystem as `/tmp`.

```bash
mkdir -p results/setup/sources
python3.10 -m venv results/setup/environments/p4net
python3.10 -m venv results/setup/environments/p4utils
python3.10 -m venv results/setup/environments/tutorial

results/setup/environments/p4net/bin/python -m pip download --no-deps \
  --only-binary=:all: p4net==1.8.0 --dest results/setup/sources
curl --fail --location \
  https://codeload.github.com/nsg-ethz/p4-utils/tar.gz/83b118bbae530b31cc74e7fa32f9174f7c0a1184 \
  --output results/setup/sources/p4utils.tar.gz
curl --fail --location \
  https://codeload.github.com/p4lang/tutorials/tar.gz/15d780e5ac7046aa64d64270ab0ef3852f1103f9 \
  --output results/setup/sources/tutorials.tar.gz
tar -xzf results/setup/sources/tutorials.tar.gz --directory results/setup/sources

results/setup/environments/p4net/bin/python -m pip install \
  -r collection/requirements/p4net310.txt
results/setup/environments/p4utils/bin/python -m pip install \
  -r collection/requirements/p4utils310.txt
results/setup/environments/tutorial/bin/python -m pip install \
  -r collection/requirements/tutorial310.txt
```

Expose the system Mininet package in the baseline environments:

```bash
python3 - <<'PY'
import subprocess
from pathlib import Path

for name in ("p4utils", "tutorial"):
    python = Path("results/setup/environments") / name / "bin/python"
    purelib = subprocess.check_output(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        text=True,
    ).strip()
    (Path(purelib) / "mininet").symlink_to("/usr/lib/python3/dist-packages/mininet")
PY
cp collection/config.example.json results/setup/config.json
```

Configuration paths are relative to the configuration file. Adjust worker and
archive paths for other locations. Keep `wrapper_interpreter` at `/usr/bin/python3`. Keep each virtual-environment `bin/python` path as the launch
path; resolving its symlink selects the base interpreter instead.

Preparation checks archive hashes, compares installed or extracted sources with
the archives, checks worker package versions, and records native executable and
Mininet identities. The P4-Utils and tutorial archive SHA-256 values are
`6d5e7e7e9160d0d47d49e149ed66923e8357c5a4e8a5ac5080906898adcdbeb2` and
`3df99eedfe95d191852bc14a579028bec6e50b8c198176f140ec97fc73f32e7b`.

## Prepare and qualify

```bash
python collection/collect.py prepare --config results/setup/config.json \
  --output results/fresh
sudo env "PATH=$PATH" python3 collection/collect.py qualify --output results/fresh
```

Preparation starts no workload. It binds the runtime, workload, plans, and
installed dependencies. Each output directory must be new. Moving the runtime
or changing bound inputs requires a new preparation.

Qualification runs six ordinary checks and 18 diagnostic checks: three tools,
1/16 switches, and native/off/stages/detail entries. It checks connectivity,
ordinary cleanup, common configuration, and diagnostic trace completeness.
These checks use boundary observations without the performance sampling window.
A failed check retains its records. After a fix, create a new preparation and
qualification attempt.

## Run sessions

Reboot after preparation and qualification. Close unrelated applications and
leave the host idle during collection. Preserve CPU and memory limits between
sessions. Each campaign uses three sessions with distinct Linux boot identifiers.

Execution requires root, `--execute`, a session number, and an initial
`--confirm-ready`. Later calls in the same session reuse that confirmation.
The default limit is one task; increase `--limit` for a larger batch.

```bash
sudo env "PATH=$PATH" python3 collection/collect.py run --output results/fresh \
  --campaign formal --session 1 --phase scale --confirm-ready --execute --limit 150
sudo env "PATH=$PATH" python3 collection/collect.py review --output results/fresh --campaign formal \
  --session 1 --gate scale --decision passed --reason "Scale evidence checked"
sudo env "PATH=$PATH" python3 collection/collect.py run --output results/fresh \
  --campaign formal --session 1 --phase fault --execute --limit 180
sudo env "PATH=$PATH" python3 collection/collect.py review --output results/fresh --campaign formal \
  --session 1 --gate fault --decision passed --reason "Fault evidence checked"
```

Formal collection inspects each terminal task before launching the next. A phase
review is required before fault collection, and both reviews are required before
the next session. Review history is append-only. Performance eligibility checks
cover both initial and restart executions, including ordinary-stop timeouts and
incomplete cleanup.

Observer calibration first runs three qualification stages. Each stage requires
a review before the next stage can run:

```bash
sudo env "PATH=$PATH" python3 collection/collect.py run --output results/fresh \
  --campaign observer --session 1 --phase qualification --confirm-ready --execute --limit 9
sudo env "PATH=$PATH" python3 collection/collect.py review --output results/fresh --campaign observer \
  --gate qualification-stage1 --decision passed --reason "Stage 1 evidence checked"
```

Repeat for `qualification-stage2` and `qualification-stage3`. Then run
`--phase calibration`. The initial calibration block requires a
`calibration-wiring` review before the remainder can run. Qualification stays
separate from the 270 calibration tasks.

```bash
sudo env "PATH=$PATH" python3 collection/collect.py run --output results/fresh \
  --campaign diagnostic --session 1 --confirm-ready --execute --limit 12
sudo env "PATH=$PATH" python3 collection/collect.py review --output results/fresh --campaign diagnostic \
  --gate one-switch-wiring --decision passed --reason "One-switch wiring checked"
```

The next 12 diagnostic tasks require the `sixteen-switch-wiring` review. Then
continue the session. Each diagnostic session contains 120 tasks. Both
calibrations keep the common 10-second hold. Diagnostic calibration disables
periodic sampling and stack capture and retains CPU and memory endpoint reads.

## Resume and retry

Rerun a command to resume its session. Terminal attempts are skipped, including
failures and timeouts. A retry must explicitly select an existing planned ID:

```bash
sudo env "PATH=$PATH" python3 collection/collect.py run --output results/fresh \
  --campaign formal --session 1 --phase scale --execute --retry PLANNED_ID
sudo env "PATH=$PATH" python3 collection/collect.py review --output results/fresh --campaign formal \
  --session 1 --gate continuation --decision passed --reason "Retry evidence checked"
```

Each retry gets a new attempt number. Formal collection requires a positive
continuation review after retries. Observer and diagnostic gate reviews can
select the latest retained attempts for advancement. First attempts remain the
primary results, and retries remain separate history.

Raw journals are under `formal/journal`, `observer/journal`, and
`diagnostic/journal` within the output directory. They retain worker events,
native outcomes, ordinary cleanup evidence, and available measurements. Formal
execution reports, observer gate records, and the diagnostic event ledger record
progress through the schedules.

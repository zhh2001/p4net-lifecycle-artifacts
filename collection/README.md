# Fresh collection

`collect.py` prepares and runs the three campaigns using the lifecycle engines in `runtime/`. Use a checkout or an extracted source distribution for collection. The analysis wheel provides the separate offline reproduction command.

Generate schedules without root or installed native tools:

```bash
python collection/collect.py plan --output results/fresh-plans
```

The schedules contain 990 formal tasks, 270 observer calibration tasks, and 360 diagnostic calibration tasks. The observer plan additionally includes nine qualification tasks. Their order, treatments, and observation windows follow the distributed protocol.

See [installation and execution](../docs/collection.md) for environment setup, native qualification, session confirmation, gate reviews, and explicit retries. Fresh results stay under the selected output directory.

Code in this directory uses Apache-2.0. Allocation data use CC BY 4.0.

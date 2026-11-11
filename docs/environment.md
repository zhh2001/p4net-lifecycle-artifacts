# Recorded experiment configuration

The campaigns used one Intel Core i5-13500H computer under WSL2, with 16 logical processors visible to the guest and an 8 GiB guest memory limit. The kernel was Linux 6.6.87.2-microsoft-standard-WSL2. Each campaign used three separately restarted sessions with unchanged CPU and memory limits.

Every tool worker used Python 3.10.20, p4c 1.2.5.10, and BMv2 `simple_switch_grpc` 1.15.0-2bdd0b7b. P4net was released v1.8.0. The baseline revisions were P4-Utils `83b118b` and official tutorials `15d780e`; both used Mininet 2.3.0-1.1. Tool-specific Python dependencies are reproduced in Table 1. The common launch wrapper used Python 3.12.3. Workers selected the pure-Python Protocol Buffers implementation.

The workload used independent switch groups, each with two hosts and a common IPv4 L3 P4 program. Each pair was probed in both directions. Final BMv2 and host settings were matched while native construction, compilation reuse, cleanup, and common setting completion remained timed task work. Tasks started with fresh compilation artifacts, with operating-system page caches retained.

The common enclosure used private PID, network, mount, IPC, and UTS namespaces. Fault episodes preserved the initial ordinary resource audit before fixture release. Restart reused the same enclosure, names, addresses, and service ports after confirming initial worker exit. Native startup cleanup remained enabled.

Idle observation used a 10-second window, 100 ms spacing, and 101 endpoints. Ordinary-stop limits were 30 seconds for scale runs and 10 seconds per fault-episode execution. Readiness limits were 120 and 90 seconds, respectively.

These are the conditions represented by the distributed observations. The offline analysis itself uses only Python's standard library; plotting additionally uses Matplotlib and Times New Roman.

# Reverse httptun diagnostics

This package measures the current HTTP/1.1 Batch v2 baseline. It does not enable
profiles B–F and does not change the v2 wire format.

## What is ready

- `run-local-diagnostics.sh` runs the httptun tests, `cargo check --lib --locked`,
  and a whole-body buffering matrix with 50/250/1000 ms delay.
- `run-corp-diagnostics.sh` is the single Mac command for the VPN window. It
  starts an isolated px on `127.0.0.1:3129`, a deterministic target on
  `127.0.0.1:13131`, and both reverse endpoints. It measures the Mac routes and
  asks the VPS to run the application suite through `127.0.0.1:13130`. Mac SSH
  is not used.
- `windows-edge-corp-profile.ps1` opens an SSH forward and a persistent, separate
  Edge profile. Its PAC sends only `beeline.ru`, `vimpelcom.ru`, and their
  subdomains through reverse httptun; all other hosts use `DIRECT`.
- `install-vps-diagnostics.sh` installs a server binary with an atomic rollback,
  adds the loopback-only `diag` endpoint, and enables the authenticated control
  runner. Existing `probe` remains on `127.0.0.1:13129`.

The control runner is disabled unless the server starts with
`--reverse-diagnostics`, requires server bearer authentication, accepts only an
already configured and claimed loopback reverse endpoint, permits one run at a
time, and caps a run at three passes.

## Corporate run

Prerequisites on the Mac:

- Cisco VPN is connected;
- a live Kerberos ticket is visible to `klist`;
- `~/.local/bin/px` exists;
- `~/.telemost-vpn/httptun-token` contains the existing one-line token;
- the diagnostic release archive has been unpacked.

Run from the unpacked archive:

```bash
./diagnostics/run-corp-diagnostics.sh
```

Use `--quick` only for troubleshooting. `--trace` attempts an optional 96-byte
packet capture of encrypted VPS TLS traffic. If passwordless `sudo` is not
available, capture is marked skipped and the main run continues.

Results are written under
`~/.telemost-vpn/diagnostics/diag-<UTC timestamp>/` and packed next to that
directory as `.tar.gz`:

- `report.json` — unified machine-readable report;
- `measurements.csv` — one row per check;
- `summary.md` — p50/p95/p99 and findings;
- `client-events.jsonl`, `target-events.jsonl`, `control-events.jsonl` — local
  monotonic transport events;
- `mac-resources.csv` and VPS resource samples;
- sanitized SSO route endpoints without query strings.

The scripts never copy the bearer token. Reports contain no request headers,
cookies, page bodies, SSO query parameters, or credentials. The optional pcap
is limited to encrypted TCP/443 traffic to the VPS.

## Windows Edge profile

Run in PowerShell from the unpacked Windows archive:

```powershell
.\windows-edge-corp-profile.ps1
```

The script does not change Windows system proxy settings or the default Edge
profile. Closing that Edge window stops its PAC server and SSH forward; the
persistent profile remains in `%LOCALAPPDATA%\TelemostCorpEdge`.

## Known baseline finding

The local end-to-end run currently records one correctness finding: a TCP
half-close from the VPS side closes the reverse direction before the target's
final response is delivered. It is reported as `half_close: eof`. Do not treat
that row as a setup failure; preserve it for the baseline report. Other harness
failures, inability to claim `diag`, or a top-level job status of `error` are
setup/runtime problems and should be investigated.

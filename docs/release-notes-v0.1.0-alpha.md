<!--
  Body text for the GitHub release page (`gh release create --notes-file`), not a
  doc meant to be read in place. Its links are deliberately relative to the REPO
  ROOT, which is what a release body resolves against — so they look broken if you
  open this file inside docs/. Leave them as they are.
-->

**Pre-alpha. Unaudited. Source only.** A per-application proxifier for Windows —
route each app's connections through the proxies you choose, by rule.

This first tag is honest about where it is: ProxiMight **sees and blocks** real
per-application connections today. It does not yet **redirect** them to a proxy
on any verified basis.

![ProxiMight connections view](docs/screenshots/connections.png)

<sub>Live per-app verdicts on the simulated backend — Proxy (single or via a chain), Direct, and Block.</sub>

---

## What works

- **Per-app attribution** — the exact owning process for every outbound connect,
  via WinDivert's socket layer.
- **Real blocking** — a `Block` rule drops the connect; the app sees it fail.
- **Rules** — app / host / port globs, ordered first-match-wins, drag to reorder.
- **Proxy protocols** — SOCKS4, SOCKS4a, SOCKS5 (+user/pass), HTTP CONNECT.
- **Chains** — multi-hop, each handshake riding inside the previous tunnel.
- **Proxy checker** — reachability, handshake, latency, ICMP ping, per-hop chain
  checks, plus an MTR-style path view.
- **VPN ingestion** — OpenVPN `.ovpn` and WireGuard `.conf`, tunnel control
  driving the vendor clients, with a verified handshake.
- **Encrypted profile at rest** — sealed with DPAPI; existing plaintext profiles
  migrate on first load.
- **GUI** — light/dark, nine panels, DPI-aware, single self-contained binary.

## What does not work yet

Read this part. It is the difference between a tool and a promise.

- 🔴 **Traffic redirection is unproven on the wire.** The rewrite (NAT the flow
  to a local relay and back) is implemented and unit-tested, but **no packet has
  ever been observed** going through it. `caps.real` is `false` and the UI says
  so. Procedure to verify: [`docs/SETUP-WINDIVERT.md`](docs/SETUP-WINDIVERT.md).
  Heads up: on a modern Windows 11 machine, **Memory Integrity and the
  vulnerable-driver blocklist refuse to load WinDivert**, so the real backend may
  not run at all without relaxing that (a deliberate security trade-off).
- 🔴 **The kill switch does not actually block.** Lockdown runs on a *stub*
  firewall that logs what it would block. Real WFP enforcement is next.
- 🟠 **Host-NAME rules cannot match.** The backend sees numeric addresses only
  (the app resolved the name before connecting), so `*.example.com` never fires.
  ProxiMight now warns you instead of failing silently — use IP patterns.
- 🟠 **OpenVPN's management socket has no password**, so any local process can
  stop your tunnel.
- 🟠 **No external security audit.** Two adversarial review passes were run by
  the author; that is not the same thing.
- ⚪ **macOS** is scaffolding that has never been compiled. **IPv6 and UDP** are
  refused rather than approximated.

## Security work in this release

Two review passes, the second auditing the first's diff — which is how the most
interesting bug was found. Every fix has a regression test.

- A **kill switch that silently stopped engaging** after a mode change, an
  unrecognized mode degrading to fail-open, and a failed `engage()` reported as
  "blocking".
- **Config injection through `.ovpn` inline blocks** — a `remote` hidden in a
  tag we did not recognize became a real tunnel endpoint, and endpoints feed the
  kill-switch allowlist.
- **Two proxy-bypass paths in the NAT table**: evicting a live flow when full,
  and — introduced by the first fix, caught by the second review — dropping a
  mapping while the application's socket was still open.
- A **Winsock refcount race** that could tear down every socket in the process,
  a **shutdown use-after-free**, a **4 KB pipe deadlock**, and a save path that
  could **destroy your profile** if a rename failed.

Full list: [`CHANGELOG.md`](CHANGELOG.md) ·
threat model and known gaps: [`docs/PRIVACY-SECURITY.md`](docs/PRIVACY-SECURITY.md)

## Building

Source only, deliberately. WinDivert is **not** bundled — it is LGPLv3/GPLv3 and
a kernel driver, and you should download and signature-verify your own copy so
the trust chain stays yours.

```bash
tools/build.ps1 -Preset windows-release
```

Needs Visual Studio 2022 with "Desktop development with C++". Without the
WinDivert SDK you get the stub backend (the full UI and rule engine, with
simulated traffic). To see real connections, follow
[`docs/SETUP-WINDIVERT.md`](docs/SETUP-WINDIVERT.md).

## Do not use this for anything that matters

It is unaudited pre-alpha software whose core redirection path has never been
observed working. If a traffic leak would harm you, wait.

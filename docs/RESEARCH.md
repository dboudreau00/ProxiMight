# ProxiMight — technical research & architecture brief

*Authored from domain research during the initial build. Where something is
gated behind a vendor (code-signing, Apple entitlements, admin/root), it is
called out plainly — those gates shape the roadmap more than the code does.*

---

## 1. Executive summary

A "proxifier" forces arbitrary applications — including ones with no proxy
support — through proxies chosen by user rules. The **rule/chain/proxy/checker/
kill-switch engine is ordinary application code** and is fully buildable and
testable today (it is, in `XaultWallet`-style portable C, and it runs). The
**hard, gated part is per-application traffic redirection**, which is deeply
OS-specific:

- **Windows** — tractable *without* writing our own signed kernel driver, by
  using the pre-signed, redistributable **WinDivert** or **Wintun** drivers from
  user space. A "real Proxifier" would instead ship a **WFP kernel callout
  driver**, which needs an EV certificate plus Microsoft attestation signing.
- **macOS** — genuinely gated. The correct per-app mechanism is a
  **NetworkExtension system extension**, which requires an Apple **special-
  approval entitlement**, a paid developer account, and notarization. A
  dev-grade fallback (`pf` + `utun` + a local SOCKSifier) works but cannot do
  reliable per-process attribution.

ProxiMight is therefore built around a **pluggable backend interface**
(`pmx_backend`) with a working **stub backend** so the entire product is
runnable now, and the platform backends land behind the same contract.

## 2. Recommended tech stack (what shipped)

| Concern | Choice | Why |
|---|---|---|
| Language | **C11** for the engine; a thin **C++17** shim for the GUI backend | "C where possible"; C++ only where the toolkit forces it |
| GUI | **Dear ImGui** via **cimgui** (C API) + **GLFW** + **OpenGL 3** | full control of the custom chain-link look, drag-and-drop, light/dark, one self-contained binary |
| JSON | **cJSON** | tiny, MIT, profile persistence |
| Build | **CMake ≥ 3.24** + **Ninja**, deps via **FetchContent** | reproducible, VS-bundled toolchain, no system installs |
| Windows redirect (planned) | **WinDivert** / **Wintun** + per-PID lookup via `GetExtendedTcpTable` | signed redistributable driver, no EV cert needed |
| Windows kill-switch (planned) | **WFP** (`fwpuclnt`) dynamic filters, or `netsh advfirewall` | default-deny + allowlist; auto-cleans on handle close |
| macOS redirect (planned) | **NetworkExtension** (`NEAppProxyProvider`) or `pf`+`utun` | the only real per-app path; pf is the dev fallback |
| macOS kill-switch (planned) | **pf** anchors via `pfctl` | block-out-all + pass to proxy endpoints |

The proxy protocol clients (SOCKS4/4a/5, HTTP CONNECT) are implemented directly
in C — they are small, well-specified wire formats and carry no dependency.

## 3. Module architecture

```
                         ┌──────────────────────────────────────────┐
   GUI (cimgui, C)  ───► │  pmx_engine  (orchestrator)              │
   pumps once/frame      │   • resolves flows -> decisions          │
                         │   • records connection events            │
                         │   • drives the lockdown health watcher   │
                         └───┬───────────┬───────────┬──────────────┘
                             │           │           │
             ┌───────────────▼──┐  ┌─────▼──────┐ ┌──▼───────────────┐
             │ pmx_profile      │  │ pmx_checker│ │ pmx_lockdown     │
             │  proxies / rules │  │ (threaded) │ │  state machine + │
             │  chains / policy │  │            │ │  pmx_firewall    │
             │  (JSON on disk)  │  └─────┬──────┘ └──┬───────────────┘
             └──────────────────┘        │           │
                        rule matching     │  proxy    │ firewall backend
                        pmx_rule/chain     │  clients  │ (stub / WFP / pf)
                                           ▼           ▼
                                   pmx_proxy (SOCKS/HTTP over pmx_net)

           ┌───────────────── pmx_backend (redirection contract) ─────────────────┐
           │  stub (demo flows, always available)  │  windows (WinDivert)  │  macos (pf/NE)  │
           └───────────────────────────────────────────────────────────────────────────────┘
```

Key header boundaries (`include/proximight/`): `pmx_backend.h` (redirection
contract), `pmx_lockdown.h` (`pmx_firewall` contract), `pmx_engine.h`
(orchestration + resolution), `pmx_profile.h` (the data model). The engine only
ever reads/writes the profile from the pump thread, so there are no profile
locks; cross-thread hand-offs (the flow inbox, checker results) use small
mutex-guarded queues.

## 4. Data model (the `.pmxprofile` file)

A profile is JSON with: `label`, `settings` (demo traffic, DNS-through-proxy,
checker defaults), `lockdown` (policy), and arrays of `proxies`, `chains`,
`rules`, plus a `default_rule`.

- **proxy** — `id, label, type (socks5/socks4/socks4a/http/https), host, port,
  use_auth, username, password, enabled`.
- **rule** — `id, name, enabled, app (`;`-glob list), host (`;`-glob list),
  ports (spec), action (direct/proxy/block), target_kind, target_id`.
- **chain** — `id, label, mode (sequential/redundancy), hops[] (proxy ids),
  enabled`.

Rules are ordered; the first enabled rule whose criteria all match wins, else
the default rule applies. Every object carries a stable `id` so rules/chains
survive reorders and reloads.

> **Security note:** proxy passwords are currently stored in plaintext in the
> profile JSON. Encrypting the profile at rest is a roadmap item — see
> `PRIVACY-SECURITY.md`. Do not put credentials you care about in it yet.

## 5. Proxy protocols & the checker

Implemented per RFC: **SOCKS5** (RFC 1928 + 1929 user/pass), **SOCKS4/4a**, and
**HTTP CONNECT** (with Basic proxy auth). HTTPS proxy (CONNECT over TLS to the
proxy) is stubbed pending a TLS backend (mbedTLS/BearSSL are the candidates).

The **checker** does, per proxy: TCP connect (measuring latency), a proxy
handshake to a probe target (default `example.com:443`), and — optionally,
off by default — an egress-IP lookup by tunneling an HTTP GET through the proxy.
Chains are checked **hop-by-hop** so a broken link is pinpointed. Checks run on
a background worker thread; the GUI polls results, so the UI never blocks.

## 6. Kill-switch / lockdown / failover

Policy modes: **off**, **fail-closed** (block all non-allowlist egress if the
proxy drops — a true kill switch), **fail-to-backup** (promote a redundancy-
chain hop; stay restricted during failover), **fail-open** (explicitly leaky).
Options: block-until-verified at startup, DNS-leak guard, IPv6-leak guard.

The controller is a pure hysteresis state machine (N consecutive failures to
trip, M successes to restore) that delegates actual blocking to a `pmx_firewall`
backend. The **stub firewall** records and logs exactly what it *would* block;
real enforcement (WFP / pf) needs admin/root and is scaffolded.

## 7. Phased roadmap

- **Phase 0 (done):** buildable, runnable app — engine, SOCKS/HTTP clients,
  proxy checker, profiles (+JSON), chains, lockdown state machine, full GUI,
  stub backend with demo traffic, unit tests.
- **Phase 1:** the Windows WinDivert backend — capture outbound SYNs, attribute
  to a PID, relay proxied connections through a local SOCKSifier; block/direct.
- **Phase 2:** the WFP kill-switch firewall (real fail-closed enforcement).
- **Phase 3:** macOS — `pf`+`utun` dev backend first, then the NetworkExtension
  system extension (once the Apple entitlement is granted).
- **Phase 4:** TLS (HTTPS proxy + secure egress checks), profile encryption at
  rest, subaddress/address-book niceties, SOCKS5 UDP associate.

## 8. Risk register (top items)

| Risk | Impact | Mitigation |
|---|---|---|
| Windows real backend needs a signed driver | High | Use pre-signed WinDivert/Wintun; avoid shipping our own kernel driver |
| macOS per-app needs Apple special-approval entitlement | High | Ship the pf/utun dev backend; pursue the entitlement in parallel; be honest in UI |
| Kill-switch enforcement needs admin/root | Med | Stub firewall logs intent; require elevation only when arming real enforcement; fail safe |
| Plaintext credentials at rest | Med | Documented; encrypt-at-rest on the roadmap before any real use |
| cimgui/imgui API drift across versions | Low | Isolated in the GUI shim; pinned deps; verified building against imgui 1.92 |

## 9. Licensing

ProxiMight's own code is **MIT**. Dependencies keep their own licenses (Dear
ImGui MIT, cimgui MIT, GLFW Zlib, cJSON MIT). The one to watch is **WinDivert
(LGPL/GPL)** — dynamically loading its driver keeps your app's license separate,
but read its terms before redistributing the `.sys`/`.dll`. We integrate ideas
from open analogs (sing-box/mihomo rule engines, tun2socks relays, proxychains)
but do not copy their (often GPL) code.

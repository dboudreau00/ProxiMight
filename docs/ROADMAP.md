# Roadmap & current state

An honest ledger of what works today and what's ahead. "Works" means it builds,
runs, and is exercised by the app or a test.

## ✅ Works today (Phase 0)

- **Engine**: rule resolution (first-match-wins + default rule), connection
  event ring, live status counters. Unit-tested.
- **Proxy protocols**: SOCKS4, SOCKS4a, SOCKS5 (+ user/pass), HTTP CONNECT
  (+ Basic auth) — real wire encoders/parsers, unit-tested.
- **Proxy checker**: synchronous + threaded async; latency, reachability,
  handshake, optional egress-IP; per-hop chain checks.
- **Profiles**: proxies / rules / chains / lockdown policy / settings, saved as
  `.pmxprofile` JSON; round-trip unit-tested; auto-loaded and saved.
- **Chains**: sequential & redundancy modes; hop add/remove/reorder.
- **Lockdown**: fail-closed / fail-to-backup / fail-open state machine with
  hysteresis; DNS/IPv6 leak-guard flags; stub firewall that logs intended
  blocks. State machine unit-tested.
- **GUI**: dark + light themes, custom chain-link iconography, drag-to-reorder
  rules, master-detail editors for proxies/rules/chains, live connections + log
  view, checker panel, lockdown panel, settings. DPI-aware; native system font.
- **Stub backend**: demo-traffic generator so the full pipeline is live without
  any driver.
- **Build/tests**: CMake + presets + VS dev-shell scripts; 6 CTest suites.

## ✅ Landed in Phase 1

- **Per-app attribution** (`pmx_procinfo`): resolves a TCP connection to its
  owning PID and image name/path via `GetExtendedTcpTable` +
  `QueryFullProcessImageName`. Unit-tested against this process (`test_procinfo`).
- **End-to-end SOCKS5 proof** (`test_socks_e2e`): stands up a minimal SOCKS5
  server and an echo server on loopback and pushes real bytes through
  `pmx_proxy_handshake` — the proxy client is verified on the wire, not just at
  the encoder level.
- **WinDivert monitor backend** (gated on the SDK): opens WinDivert's SOCKET
  layer, which reports each connect with the owning ProcessId, so ProxiMight can
  show **real applications and real destinations** classified by your rules.
  Runs in sniff mode — observation only.
- **CMake SDK auto-detection** (`third_party/windivert` or `PMX_WINDIVERT_DIR`),
  which stages `WinDivert.dll`/`.sys` next to the executable; falls back to the
  stub when absent. See `SETUP-WINDIVERT.md`.
- **Backend switching in Settings** + a `--panel=<name>` startup flag for
  jumping straight to a panel.

## 🔶 Not yet real (the honest gaps)

- **No *proven* traffic redirection.** With the WinDivert SDK you can see real
  per-app connections and **blocking genuinely works** (Phase 1b took the handle
  out of sniff mode; `caps.can_block` is true). Proxying is the unproven part:
  the rewrite is written end to end but no packet has been observed on the wire,
  so `caps.real == false` and the UI still says so.
- **No real firewall enforcement.** Lockdown logs what it *would* block.
- **No automatic failover.** A *redundancy* chain resolves to its first hop
  without consulting health, and lockdown's *fail to backup* mode promotes
  nothing — it engages the firewall exactly like *fail closed*. Both are safe
  (they block rather than leak) but neither delivers the continuity the names
  suggest. Wiring the checker's health into resolution is the missing piece.
- **HTTPS proxy** (CONNECT over TLS to the proxy) returns `UNSUPPORTED` — needs
  a TLS library.
- **Credentials at rest**: the profile is now **sealed** (DPAPI on Windows) so
  passwords no longer hit disk in cleartext; a legacy plaintext profile is
  migrated on first load. Residual limits (same-user malware, non-Windows still
  plaintext, no password-derived option yet) are in `PRIVACY-SECURITY.md`.

## ✅ Landed in Phase 1b

- **Thread-safe decision path.** `pmx_engine_decide()` answers from a snapshot
  of the profile republished each pump, so a backend can get an inline verdict
  from its own thread while the live profile stays lock-free. Backends bind it
  via the optional `set_decide_cb`. Semantics tested in
  `test_decide_snapshot.c`.
- **Real blocking on Windows.** The WinDivert handle is no longer sniff-only:
  `DIRECT` connections are re-injected and `BLOCK` connections are dropped, so
  per-app blocking genuinely works. `caps.can_block` is now true.
- **Fail-closed by default when we can't proxy.** A `PROXY` verdict can't be
  honoured until redirection lands, so rather than leak the connection out
  unproxied, it is blocked. `cfg.block_when_cannot_proxy` (derived from the
  lockdown mode) lets you opt into allow-direct instead — leaky, but explicit.
- **The relay** (`pmx_relay`): a local SOCKSifier that takes a registered
  (source port → destination, proxy) mapping, performs the proxy handshake and
  splices bytes. Driver-independent and proven end-to-end in `test_relay.c`,
  including that it drops unregistered connections instead of acting as an open
  proxy.
- New socket primitives (`pmx_tcp_listen/accept/connect_from`, `pmx_wait_two`)
  so the relay and the test harness are portable C.

## ✅ VPN ingestion & path diagnostics

- **OpenVPN (`.ovpn`) and WireGuard (`.conf`) ingestion** (`pmx_vpn`). Parses
  endpoints, DNS, MTU, AllowedIPs/redirect-gateway (so we know if it's a full
  tunnel), cipher/auth, and device. Imported from the UI via a native file
  dialog, persisted in the profile, and shown in a **VPN tunnels** panel.
  - **Secrets policy:** the parser never copies key material. It records only
    that a `PrivateKey` / `PresharedKey` / inline `<key>`/`<tls-auth>` block is
    *present*, and keeps the path to the original file — which is what gets
    handed to the vendor client. `test_vpn` asserts no secret bytes appear
    anywhere in the parsed struct.
  - The parser also refuses to treat directive-looking text inside inline
    `<ca>`/`<key>` blocks as configuration (a certificate body containing
    "remote evil.example.com" must not add an endpoint). Tested.
- **The kill-switch now allowlists VPN endpoints.** Arming lockdown without
  that would block the tunnel's own handshake — a kill switch that bricks the
  link it is supposed to protect.
- **Ping + MTR** (`pmx_netpath`): ICMP round-trip and a traceroute that keeps
  per-hop loss / best / avg / worst, like `mtr`. Uses the Windows IP Helper ICMP
  API, so **no Administrator required**. The proxy checker gained a **Ping**
  column (raw network distance) next to **Handshake** (what the proxy itself
  costs), plus a **Network path** card with an async hop table.

- **Tunnel control** (`pmx_vpn_run` + `pmx_proc`): Connect/Disconnect drives the
  vendor client as a child process —
  `wireguard.exe /installtunnelservice <conf>` (needs Administrator, and says so
  up front rather than failing obscurely) or `openvpn.exe --config <conf>`
  (the OpenVPN interactive service handles the privileged parts). The client is
  auto-detected with a per-profile override path, and the UI prints the exact
  command Connect will run.

**Deliberately still honest:** the state is reported as **"Client running"**, not
"Connected". ProxiMight starts the client and watches the process; it does not
yet read WireGuard's transfer counters or OpenVPN's `--management` socket, so
claiming a verified handshake would be a guess. Reading one of those is the next
increment.

**Not done:** ProxiMight does not implement tunnel crypto and never will — it
drives the vendor clients, the same rule as not bundling WinDivert.

## 🔶 Phase 1c — the packet rewrite (written, not yet proven on the wire)

The redirect path is now implemented end to end:

1. The SOCKET layer decides a flow should be proxied and — while it still has
   the source port — registers the real destination and proxy with the relay
   (`pmx_relay_register`) and the NAT table (`pmx_nat_add`), then lets the SYN
   out.
2. A second handle at `WINDIVERT_LAYER_NETWORK` rewrites that flow so both
   endpoints are loopback (`127.0.0.1:<sport>` → `127.0.0.1:<relay>`), and
   rewrites replies back to look like they came from the original destination.
   Checksums are redone with `WinDivertHelperCalcChecksums()`.
3. The relay performs the proxy handshake and splices the bytes.

The capture filter is scoped so ProxiMight can never recapture its own injected
packets — the outbound clause excludes traffic already bound for loopback, and
the inbound clause matches only replies from the relay port. Without that, the
rewrite loops forever.

**What is and isn't verified.** The NAT table (`test_nat`) and the relay
(`test_relay`, through a real SOCKS5 server) are covered by tests, and the whole
thing compiles against the real WinDivert headers. The *on-the-wire* behaviour —
whether Windows accepts the rewritten loopback packets exactly as intended — has
not been observed, because that needs an elevated run gating live traffic. Until
someone confirms it on a real machine, `caps.real` stays **false** and the UI
keeps its "not redirecting real traffic" banner. See SETUP-WINDIVERT.md for a
low-risk way to try it.

**Multi-hop chains are carried properly.** The relay connects to hop 1, asks each
hop to reach the next, and asks the last for the real destination — every
handshake riding inside the tunnel the previous one established
(`test_relay_chain` proves it through two real SOCKS5 servers). A *redundancy*
chain is a set of alternatives rather than a path, so only its first hop is
traversed.

**Refusals are deliberate.** Chain resolution is all-or-nothing: if any hop is
missing or disabled, the flow fails closed rather than going out through fewer
hops than asked for. Under-proxying misrepresents the user's protection, which
is worse than not proxying. IPv6 is refused the same way. The socket layer also
fails closed if relay/NAT **registration** fails, and the NAT table fails closed
when it is full of live flows (reclaiming only free/expired slots, and dropping
a flow's entry as soon as its relay connection ends) rather than evicting — and
so silently un-proxying — an active connection. See `docs/PRIVACY-SECURITY.md`.

### Remaining for Phase 1c to be "done"
- Confirm the rewrite on a live elevated run; flip `caps.real`. **Everything it
  depends on is now built, tested and twice-reviewed** — this is the one step
  left, and it needs a human at an elevated prompt (see
  `docs/SETUP-WINDIVERT.md` for the low-risk procedure).
- IPv6, and UDP (SOCKS5 UDP associate).

**Resource semantics settled (2026-07-25).** The NAT table never evicts a live
flow: it fails closed when full of live entries, reclaims free/expired/finished
ones, and a flow whose relay side ended keeps its mapping (so late packets are
still rewritten to the relay rather than leaking direct) while becoming
reclaimable. The socket layer fails closed if relay/NAT registration fails. The
flow inbox is bounded, and dropped flows are counted and surfaced.

## 🔜 Phase 2 — Windows kill-switch (WFP)

- `fwpuclnt` dynamic filters: block-all-outbound + permit proxy endpoints and
  loopback; optional block `:53` and all IPv6. Auto-clean on handle close.
- Implement the `pmx_firewall` vtable; requires Administrator.

## 🔜 Phase 3 — macOS

- Dev backend: `pf` rdr/route-to into a `utun` transparent SOCKSifier.
- Real backend: a `NEAppProxyProvider` system extension (Swift/ObjC bridged to
  the C core) — pending Apple's NetworkExtension entitlement + notarization.
- `pf`-anchor kill-switch firewall.

## 🔜 Phase 4 — polish & features

- TLS (mbedTLS/BearSSL): HTTPS proxy + encrypted egress checks.
- Profile encryption at rest: **done on Windows** via DPAPI (`pmx_protect`),
  transparent, no prompt. Still open: a password-derived key (KDF unlocked at
  launch) for at-rest protection against same-user offline access, and a
  Keychain/`libsecret` provider so macOS/Linux stop writing plaintext.
- SOCKS5 UDP associate; subaddress list; address book; import from Proxifier
  `.ppx`.
- Optional SOCKS5 proxy (`--proxy`) for Tor users; leak-tested. (Do **not**
  bundle Tor.)

## Non-goals

- Bundling or auto-downloading any redirection driver or Tor binary — the user
  supplies and trusts their own.
- Shipping our own EV-signed kernel driver in the near term.
- Presenting ProxiMight as a VPN or as production-safe before a security review.

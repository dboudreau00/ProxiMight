# Changelog

All notable changes to ProxiMight. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/), with `0.x` meaning the API can still move.

## [0.2.0-alpha] — 2026-07-25

A whole-project validation pass: both presets built and tested, the GUI inspected
by screenshot, and a multi-agent read-only audit whose high-severity findings were
each re-verified by hand against the source before anything was changed.

Minor rather than patch because behaviour changed in ways a user can observe (UDP
now fails closed, NAT entries expire on idle rather than age, deleting a proxy
leaves a sequential chain broken-but-visible instead of silently shorter) and the
public surface grew (`pmx_engine_status.backend_can_block`, `gui_button_width`,
`guix_set_window_icon`, `guix_set_titlebar_theme`). Still `-alpha`: redirection
remains unproven on the wire, which is the only thing that lifts the suffix.

### Fixed — proxy-bypass paths in the redirect layer

All three would have sent traffic **direct** while the UI or log claimed it was
being proxied. None had ever run on the wire (`caps.real` is still `false`), so
none of them shipped as a live leak — but each was reachable the moment it did.

- **A live flow lost its NAT mapping after 120 s.** Expiry was measured from the
  CONNECT and nothing refreshed it, so every proxied connection outlasting the
  TTL — a long download, SSH, a websocket — stopped being rewritten mid-stream
  and its next segment left for the real destination from the real source IP.
  That is precisely the bypass the table's no-evict-a-live-entry policy exists to
  prevent, arrived at through the clock instead of through eviction. Expiry now
  tracks **inactivity**, and a lookup counts as activity. Regression test added,
  and confirmed to fail against the old behaviour.
- **UDP with a `Proxy` verdict was allowed out unproxied.** The socket layer
  accepts UDP and registered it with the relay and NAT table, but the network
  filter begins `"tcp and"`, so no datagram was ever diverted — DNS and QUIC left
  in the clear while the log said `redirecting`. UDP now fails closed like IPv6,
  with the reason named in the warning.
- **ProxiMight could proxify itself.** Nothing compared the connecting PID to our
  own, so an ordinary "any application → proxy" rule matched the relay's own
  connection to the upstream proxy, registered it, and the network layer rewrote
  it back into the relay. The capture filter already prevented recapturing
  packets we *inject*; this covers the ones we *originate*.
- **The outbound rewrite matched on source port alone.** Ephemeral ports get
  recycled, so a new connection elsewhere could inherit a still-live entry and be
  dragged into the relay and handed the previous flow's destination. The packet's
  destination must now match the one recorded.

### Fixed — the kill switch could watch nothing and call it healthy

- **The health watcher went silent when its proxy disappeared.** The proxy to
  probe was chosen once, at Start, and never re-derived. Delete or disable it
  while running and `pmx_profile_find_proxy` returned NULL, so no probe was
  submitted, `pmx_lockdown_on_health` was never called, and lockdown sat on its
  last verdict — normally "Armed — healthy" — indefinitely, reporting protection
  for a proxy that no longer existed. It now re-derives each tick and, when there
  is no enabled proxy left, reports the path **down**: a kill switch with nothing
  to watch has failed and must trip.
- **The VPN allowlist was equally frozen.** Same single call site, so a tunnel
  enabled after Start never reached the allowlist — and arming lockdown then
  blocked the very handshake the allowlist exists to protect. Rebuilt on the same
  tick, and only pushed to the firewall when it actually changed, so real WFP
  filters are not re-created every few seconds.
- **The background watcher inherited the opt-in egress probe.** Both checkers
  were handed the same options, so switching on the egress-IP check — documented
  as a deliberate, one-off leak for a manual test — silently became an HTTP GET
  to a third-party IP-echo service every health interval: roughly 900 requests an
  hour at the 4 s default. The watcher now gets reachability and the proxy
  handshake only; egress and ICMP ping are stripped.

### Fixed — deleting a proxy silently shortened a chain

A sequential chain's hops are a path, so their count and order *are* the
protection requested. Deleting a proxy compacted it out of every chain, quietly
turning a 3-hop chain into a 2-hop one and routing traffic through less
protection than asked for — the under-proxying the project refuses everywhere
else. Sequential chains now keep the reference dangling, exactly as a rule
pointing at a deleted proxy already did: the resolver is all-or-nothing on an
unresolvable hop so the flow fails closed, and the editor already rendered such a
hop as "(missing proxy)" with a Remove button, so it is visible and fixable.
Redundancy chains are an unordered *set*, so those still compact. Regression test
added.

### Fixed — build integrity

- **The build was not reproducible.** `cimgui` — which carries Dear ImGui as a
  submodule — was fetched from `master`, so a clean configure on a different day
  got a different imgui and an upstream push could break the build with no local
  change. Pinned to an exact commit (imgui 1.92.8). glfw and cJSON were already
  pinned.
- **`PMX_WERROR=ON` could not build**, despite being the documented way to
  tighten warnings: it failed 16 translation units. Third-party headers now come
  in as `SYSTEM` so their warnings are not attributed to us, and two genuine
  defects of our own are fixed — `pmx_socks.c` called `sscanf` with no
  `<stdio.h>` and `test_netpath.c` called `pmx_sleep_ms` with no `pmx_net.h`.
  Both were implicit declarations: a constraint violation since C99 that MSVC
  only warns about, and in `sscanf`'s case undefined behaviour. clang and gcc
  reject them outright, so `pmx_socks.c` — a *portable-core* file — would not
  have compiled on the macOS path. The whole tree now builds warning-free with
  `/WX`.

### Fixed — GUI

- **Numeric and text inputs collapsed inside multi-column form tables.** Cards
  are auto-resizing children, which makes a table default to fit-to-content
  sizing, and these widgets ask for width `-1` ("fill the column") — which has
  nothing to resolve against. Lockdown rendered "Failures to trip" with a
  zero-width box and clipped the health interval mid-digit; Settings did the same
  to the probe port and host. The affected tables now declare stretch columns.
- **"Save profile" rendered off the right edge** of every panel: the available
  width was measured before the heading was drawn and then used to pad after it,
  overshooting by exactly the heading's width. Right-alignment now measures from
  the real cursor position and takes the button's width from the widget itself.
- The window, taskbar and Alt-Tab now carry the interlocked chain-link mark,
  rasterized from the same geometry the UI draws; `proximight.exe` carries it in
  Explorer via an ICON resource.
- The native title bar follows the theme instead of leaving a light Windows
  caption on top of a dark UI.

### Changed — claims corrected to match the code

No behaviour change; these were places the project promised more than it does.

- README and ROADMAP said the WinDivert backend "does not proxy or block yet".
  **Blocking has worked since Phase 1b**; proxying is the unproven half.
- README, `pmx_chain.h`, `pmx_lockdown.h` and the Lockdown panel described
  **redundancy-chain failover and "fail to backup"** as working. Neither is
  built: a redundancy chain takes hop 0 without consulting health, and
  `FAIL_BACKUP` engages the firewall exactly like `FAIL_CLOSED` while labelling
  the state "Failing over". Both are *safe* — they block rather than leak — but
  they do not deliver continuity, and the mode's UI text now says so plainly.
- README listed **HTTPS** among working proxy types; it returns `UNSUPPORTED`.
- The dashboard banner and the Settings backend card described the WinDivert
  backend as a **simulation showing demo traffic**, keyed off `caps.real`. But
  `caps.real` tracks whether *proxying* has been proven on the wire, and that
  backend sees and blocks real connections for real — so the warning understated
  what was happening on the user's machine. `pmx_engine_status` now carries
  `backend_can_block` so the two can be told apart, and each case gets its own
  wording.
- `pmx.h` claimed to "pull in the whole engine" while omitting `pmx_socks.h` and
  `pmx_http_connect.h`.
- `SECURITY.md` pointed at GitHub private vulnerability reporting with no
  fallback for when it is not switched on.
- The blanket "every fix has a regression test" is now accurate about what the
  unit suite can and cannot reach.

### Known limitations unchanged

Redirection is still unproven on the wire, lockdown still uses the stub firewall,
there is still no external audit, and macOS is still uncompiled scaffolding. One
thing the audit sharpened: the socket layer's byte order is only *self*-consistent
with the packet layer, which reading cannot distinguish from *both* being wrong.
If a wire test ever logs `redirecting` while `n_redirected` stays at 0, that is
the first thing to check — there is now a DEBUG line for exactly this case.

## [0.1.0-alpha] — 2026-07-25

First tagged release. **Pre-alpha, unaudited, source only.** It sees and blocks
real per-application connections today; it does not yet *redirect* them to a
proxy on a verified basis — see "Known limitations".

### Added

- **Engine** — first-match-wins rule resolution with a default rule, connection
  event ring, live counters. Backends resolve inline verdicts against a
  mutex-guarded profile snapshot, so the live profile stays single-threaded.
- **Proxy protocols** — SOCKS4, SOCKS4a, SOCKS5 (+user/pass), HTTP CONNECT
  (+Basic). HTTPS-to-proxy returns `UNSUPPORTED` (needs TLS).
- **Rules** — app / host / port glob matching, ordered, drag-to-reorder.
- **Chains** — sequential (traversed hop by hop, each handshake inside the
  previous tunnel) and redundancy modes.
- **Relay** — a local SOCKSifier that carries redirected connections and drops
  unregistered ones, so it can never act as an open proxy.
- **Per-app attribution** — exact owning PID from WinDivert's socket layer.
- **Real blocking** — a `Block` rule drops the connect.
- **Lockdown / kill-switch** — fail-closed / fail-to-backup / fail-open with
  hysteresis, and a VPN-endpoint allowlist so arming cannot block the tunnel's
  own handshake. Enforcement is still the **stub** firewall.
- **Proxy checker** — reachability, handshake, latency, ICMP ping, optional
  egress IP (off by default), per-hop chain checks.
- **Network path** — MTR-style traceroute with per-hop loss/best/avg/worst.
- **VPN ingestion** — OpenVPN `.ovpn` and WireGuard `.conf` parsing, tunnel
  bring-up/tear-down driving the vendor clients, handshake verification.
- **Profiles** — JSON model, autoload/save, stable ids.
- **GUI** — Dear ImGui, light/dark themes, chain-link iconography, nine panels.
- **Profile encryption at rest** — sealed with DPAPI on Windows; legacy
  plaintext profiles migrate transparently on first load.
- `--log=<level>` runtime flag (the redirect evidence is logged at DEBUG).

### Security fixes

Two adversarial review passes, the second auditing the first's diff. Most of the
fixes below carry a regression test; the ones that live inside the WinDivert
backend or the GUI do not, because neither is reachable from the unit suite —
`docs/PRIVACY-SECURITY.md` says which is which rather than implying uniform
coverage.

- **Kill switch could silently stop working.** Changing the mode while armed
  never re-applied enforcement, leaving a state the trip branch could never fire
  from. An unrecognized mode degraded to fail-open while reporting "Armed —
  healthy". A failed `engage()` was reported as "Tripped — blocking".
- **Config injection via `.ovpn` inline blocks.** Only ten tags were skipped, so
  a `remote` hidden in `<auth-user-pass>`, `<crl-verify>` etc. became a real
  tunnel endpoint — and endpoints feed the kill-switch allowlist. Now every
  inline block is skipped by default, matched case-sensitively like OpenVPN.
- **NAT table could bypass the proxy.** It evicted the oldest (often *live*)
  flow when full, whose packets then egressed direct. It now fails closed. The
  first fix for the teardown half introduced a second bypass — deleting the
  mapping while the app's socket was still open — corrected with
  `pmx_nat_mark_closed`.
- **Winsock refcount race** could `WSACleanup()` while sockets were live.
- **Per-`recv` timeout** let a hostile proxy stall the kill switch instead of
  tripping it; connect/read timeouts are now whole-operation deadlines.
- **Use-after-free at shutdown** — the GUI was freed before the worker threads
  that log into it were joined.
- **Saving a profile could destroy it** — `remove()`-then-`rename()` left both
  files gone if the rename failed; now an atomic single-step replace.
- Child-process capture deadlocked above 4 KB of output; new rules defaulted to
  "proxy via nothing"; `8000 - 8080` matched only its endpoints; persisted
  timeouts were unvalidated; the flow inbox was unbounded.

### Known limitations

- **Traffic redirection is unproven on the wire.** `caps.real == false` and the
  UI says so. The rewrite is implemented and unit-tested; no packet has been
  observed. Procedure: `docs/SETUP-WINDIVERT.md`. Note that on a modern Windows
  11 machine, **Memory Integrity / the vulnerable-driver blocklist will refuse
  to load WinDivert at all** — so the backend (and this test) may be unavailable
  without relaxing that. See the troubleshooting section of `SETUP-WINDIVERT.md`.
- **No real firewall enforcement.** Lockdown logs what it *would* block.
- **Host-NAME rules cannot match** on the WinDivert backend, which reports
  numeric addresses only. The app now warns instead of failing silently.
- **OpenVPN's management socket is unauthenticated** — any local process can
  stop your tunnel. Fix known, deferred because it cannot be verified without a
  real endpoint.
- **No external security audit.** Two author-run adversarial passes are not an
  audit.
- **macOS is scaffolding only** — never compiled.
- **IPv6 and UDP** are refused rather than approximated.

### Notes

- **Source-only release.** WinDivert is **not** bundled: it is LGPLv3/GPLv3 and
  a kernel driver whose trust chain you should verify yourself. See
  `docs/SETUP-WINDIVERT.md`.
- 14 CTest suites pass in Debug and Release on MSVC 19.44.

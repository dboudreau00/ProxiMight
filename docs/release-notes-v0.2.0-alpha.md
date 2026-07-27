<!--
  Body text for the GitHub release page (`gh release create --notes-file`), not a
  doc meant to be read in place. Its links are deliberately relative to the REPO
  ROOT, which is what a release body resolves against — so they look broken if you
  open this file inside docs/. Leave them as they are.
-->

**Pre-alpha. Unaudited.** A per-application proxifier for Windows — route each
app's connections through the proxies you choose, by rule.

This release is the result of a whole-project validation pass. Nothing new was
built; several things that were quietly wrong were made right, and several things
the project claimed about itself were corrected.

![ProxiMight resolving connections live](docs/screenshots/connections.gif)

## The short version

ProxiMight **sees** and **blocks** real per-application connections. It does not
yet have a *verified* ability to **redirect** them to a proxy — that path is
written and unit-tested but **no packet has ever been observed going through it**,
so `caps.real` stays `false` and a `Proxy` verdict fails closed rather than leaking
out unproxied.

## Fixed: five ways traffic could have gone direct

None of these had ever run — the redirect path has never been exercised on the
wire — but each was reachable the moment it was.

- **NAT mappings expired 120 s after the CONNECT** and nothing refreshed them, so
  any proxied connection outliving the TTL stopped being rewritten mid-stream and
  its next segment left for the real destination from the real source IP. Expiry
  now tracks inactivity.
- **UDP with a `Proxy` verdict was registered and allowed out.** The network filter
  is TCP-only, so the datagrams were never diverted — DNS and QUIC left in the
  clear while the log said `redirecting`. UDP now fails closed.
- **ProxiMight could proxify itself**: nothing excluded our own PID, so a broad
  rule matched the relay's own connection to the upstream proxy and rewrote it back
  into the relay.
- **The outbound rewrite trusted a source-port match alone**, so a recycled
  ephemeral port could drag an unrelated flow into the relay.
- **Deleting a proxy silently shortened a sequential chain**, routing traffic
  through fewer hops than requested. It now leaves a visible broken hop and fails
  closed.

## Fixed: the kill switch could watch nothing and call it healthy

The proxy to probe was picked once at Start and never re-derived, so deleting or
disabling it left lockdown reporting **"Armed — healthy"** forever for a proxy that
no longer existed. It now re-derives continuously and trips when there is nothing
left to watch. The VPN allowlist was frozen the same way — a tunnel enabled after
Start was never allowlisted, so arming lockdown blocked its handshake.

Separately, the background health watcher **inherited the opt-in egress-IP check**,
turning a deliberate one-off leak into an HTTP GET to a third-party IP-echo service
roughly 900 times an hour. It now performs reachability and the proxy handshake
only.

## Fixed: build integrity

- **The build was not reproducible** — `cimgui`, which carries Dear ImGui as a
  submodule, was fetched from `master`. Pinned to an exact commit (imgui 1.92.8).
- **`PMX_WERROR=ON` could not build**, despite being the documented way to tighten
  warnings; it failed 16 translation units. Third-party headers are now `SYSTEM`,
  and two real defects of our own are fixed — `sscanf` and `pmx_sleep_ms` were both
  called without a declaration, which is undefined behaviour in the first case and
  a hard error on clang/gcc in both. One of them was in the *portable* core, so it
  would not have compiled on the macOS path. **The whole tree now builds clean at
  `/W4 /WX`.**

## Fixed: the UI

- Numeric inputs **collapsed to zero width** inside the Lockdown and Settings form
  tables — "Failures to trip" simply did not show its value.
- **"Save profile" rendered off the right edge** of every panel.
- The window, taskbar and Explorer now carry the chain-link mark, and the title bar
  follows the theme instead of leaving a light caption on a dark UI.

## Corrected claims

The project's central promise is that it never overstates itself, so these count as
defects:

- README and ROADMAP said the WinDivert backend **could not block**. It has since
  Phase 1b.
- README, two headers and the Lockdown panel described **redundancy failover** and
  **"fail to backup"** as working. Neither is built — both are safe, because they
  block rather than leak, but neither delivers continuity.
- The dashboard called the **real backend a simulation showing demo traffic**.
- README listed **HTTPS** as a working proxy type; it returns `UNSUPPORTED`.
- The changelog claimed **every fix has a regression test**. `docs/PRIVACY-SECURITY.md`
  now records which are covered and which structurally cannot be.

## Still true, and still the ceiling

- 🔴 **Redirection unproven on the wire.** Procedure: [`docs/SETUP-WINDIVERT.md`](docs/SETUP-WINDIVERT.md).
  Note that Memory Integrity and the vulnerable-driver blocklist will refuse to load
  WinDivert on a current Windows 11 machine.
- 🔴 **The kill switch does not actually block** — lockdown runs on a stub firewall.
- 🟠 **Host-name rules cannot match** on WinDivert; the app warns per rule.
- 🟠 **OpenVPN's management socket has no password.**
- 🟠 **No external security audit.** Author-run adversarial passes are not an audit.
- ⚪ **macOS** is scaffolding that has never been compiled. **IPv6 and UDP** are
  refused rather than approximated.

One question deserves naming: the socket layer fills the NAT table without `ntoh*`
while the network layer compares against packet fields with it. That is
*self*-consistent, which is exactly what makes it undecidable by reading — "both
right" and "both wrong" look identical. If a wire test logs `redirecting` while
`n_redirected` stays at 0, that is the answer.

## Building

Source is the real deliverable. WinDivert is **not** bundled — it is LGPLv3/GPLv3
and a kernel driver, and you should download and signature-verify your own copy so
the trust chain stays yours.

```
tools/build.ps1 -Preset windows-release
```

Needs Visual Studio 2022 with "Desktop development with C++". Clone somewhere
short; Windows' 260-character path limit bites during dependency fetch. Without the
SDK you get the stub backend — the full UI and rule engine against simulated
traffic. To see real connections, follow [`docs/SETUP-WINDIVERT.md`](docs/SETUP-WINDIVERT.md).

A prebuilt **stub-backend** binary is attached for convenience. It is deliberately
built *without* the WinDivert SDK, so it is legally clean to redistribute and can
show you the entire interface and rule engine — but it cannot see or touch real
traffic. For that, build it yourself against your own verified driver.

Full list: [`CHANGELOG.md`](CHANGELOG.md) · threat model and known gaps:
[`docs/PRIVACY-SECURITY.md`](docs/PRIVACY-SECURITY.md)

## Do not use this for anything that matters

Unaudited pre-alpha whose core redirection path has never been observed working. If
a traffic leak would harm you, wait.

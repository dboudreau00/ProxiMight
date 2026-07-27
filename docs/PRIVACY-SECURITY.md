# Privacy & security notes

ProxiMight handles proxy credentials and steers network traffic, so its threat
model matters. This is an **unaudited pre-alpha** — read this before trusting it
with anything real.

## What ProxiMight is and isn't

- **It is** a router of connections to proxies you configure. Your privacy is
  exactly the privacy those proxies provide.
- **It is not a VPN.** It adds **no encryption** of its own. A SOCKS/HTTP proxy
  can see and (for plain HTTP) modify your traffic. Only end-to-end TLS between
  your app and the destination protects the payload from the proxy.

## Known issues (current build)

1. **Credentials at rest — now sealed (Windows), with limits.** The profile file
   (`profile.pmxprofile`) is **sealed at rest** before it touches disk. On
   Windows this uses **DPAPI** (`CryptProtectData`, current-user scope) via
   `pmx_protect` / `pmx_profile_save`, so `username`/`password` for each proxy no
   longer sit in cleartext. An existing plaintext profile is **migrated
   automatically** the first time it is loaded. The on-disk format is a small
   binary container (`PMXSEAL\0` magic + the sealed blob); the old plaintext JSON
   is still recognized on load so nothing breaks during the upgrade.

   **What this does and does not protect.** DPAPI binds the ciphertext to your
   Windows user on this machine: another local account can't read it, and the
   file copied to a different machine or user can't be decrypted (it will fail to
   load rather than be silently overwritten — see below). It does **not** protect
   against malware running as *you* while you are logged in — that code can call
   `CryptUnprotectData` too. It is at-rest protection, not a defense against a
   compromised session. There is **no password prompt**; the key is your Windows
   login, so a forgotten password can't lock you out, but the profile is tied to
   this account/machine (back it up by exporting, not by copying the file).

   **Platforms without a provider.** The macOS/Linux scaffolds have no at-rest
   crypto provider wired in yet, so on those builds the profile is written in
   **plaintext** and the save path logs a loud warning. A Keychain/`libsecret`
   provider behind the same `pmx_protect` seam is the follow-up there.

   **Stronger option, not yet built.** A password-derived key (a KDF unlocked at
   launch, AES-GCM) would additionally protect the file against same-user offline
   access while the app is closed, at the cost of an unlock prompt and a
   forgot-password footgun. It can layer on top of the same `pmx_protect` seam.

   **Safety valve.** If a profile exists but can't be read (sealed for another
   user/machine, or corrupt), ProxiMight runs on seeded defaults and **refuses to
   save**, so it never clobbers the file you couldn't open. Remove or fix the
   file to start fresh.

   Correctness of the above is covered by `test_protect` (seal/unseal round-trip,
   tamper rejection, sealed-on-disk with no cleartext password, and legacy
   migration).

2. **No real kill-switch enforcement yet.** Lockdown currently uses the *stub*
   firewall — it logs what it *would* block but does not actually block. Do not
   rely on it to prevent leaks yet. Real WFP/pf enforcement is Phase 2/3.

   **Three state-machine bugs were fixed on 2026-07-24** — worth knowing because
   they all made lockdown *claim* a protection it wasn't providing:
   - **Changing the mode while armed did nothing.** `set_policy` only copied the
     struct. Switching Off → *fail closed* (or *fail open* → *fail closed*) left
     the state at `INACTIVE`/`FAILED_OPEN`, and the trip branch only fires from
     `ARMED_HEALTHY` — so the kill switch could **never engage again for the rest
     of the session**, silently. Reverse direction: switching to Off left the
     firewall engaged forever with a stale label. Both now reconcile enforcement
     with the new mode.
   - **An unrecognized mode degraded to fail-open** while reporting "Armed —
     healthy". The profile parser casts the JSON int straight to the enum, so a
     corrupt or hand-edited profile could disable the kill switch invisibly.
     Unknown modes now clamp to **fail closed**.
   - **A failed `engage()` was reported as "Tripped — blocking".** The firewall's
     status was discarded and a NULL firewall counted as success. This matters
     most when real WFP lands, since it needs Administrator: an unelevated run
     would have shown a reassuring red "blocking" shield while nothing was
     blocked. A failed engage now reports `FAILED_OPEN` and logs an error.

   All four are covered by new cases in `test_chain_failover`.

3. **Egress-IP measurement is a deliberate leak.** The checker's optional
   "measure egress IP" makes a real request through the proxy to a third-party
   IP-echo service, revealing your use of that proxy to that service. It is
   **off by default**; turn it on only when you accept that.

4. **DNS & IPv6 leaks.** Even with a working redirect backend, name resolution
   and IPv6 are classic leak vectors. The lockdown policy has DNS-leak and
   IPv6-block flags, but they are only meaningful once a real firewall backend
   is wired in.

5. **Redirect-path NAT table now fails closed instead of evicting (fixed).** The
   WinDivert redirect path (still unverified on the wire; `caps.real == false`)
   keeps a per-flow NAT table of 1024 entries. It used to **evict the oldest
   entry** when full — which for long-lived flows is an *active* connection, so
   the evicted flow stopped being rewritten and egressed **direct to the real
   destination**, a silent proxy bypass above ~1024 concurrent flows. That is
   fixed: `pmx_nat_add` now reclaims a free, **expired**, or **finished** slot
   and, if the table is full of *live* flows, **fails closed** (`PMX_ERR_STATE`)
   so the socket layer blocks the new connection rather than un-proxying an old
   one.

   The teardown half was subtler, and the first attempt got it **wrong**: the
   relay's close callback originally *deleted* the NAT entry the moment its
   connection ended. But the application's socket can still be open — it is only
   then learning the connection went away — and the redirect layer rewrites a
   packet **only** when `pmx_nat_find` hits, so the app's next packet would have
   gone straight to the real destination from the real source IP. That is the
   same silent bypass, just moved to teardown, and it was *introduced* by the
   fix. The callback now calls `pmx_nat_mark_closed`: the mapping keeps matching
   (late packets still go to the relay, which refuses them) while the slot
   becomes reclaimable, so the table still cannot wedge. `test_nat` pins both
   halves — a closed flow still resolves, and its slot can be taken by a new flow
   while a live flow's never is.

6. **Checker robustness gaps against a hostile proxy (partly open).** A proxy you
   configure is trusted to move your bytes, but it is still a remote party that
   can misbehave. Two issues were fixed: `pmx_recv_exact` now bounds the **whole**
   read rather than each `recv()` (a proxy dribbling one byte at a time used to
   stretch a nominal 5 s handshake into tens of minutes, pinning the single
   checker worker — and because the lockdown state machine only advances on a
   *completed* health probe, that stalled the kill switch instead of tripping it),
   and persisted timeouts/counters are clamped on load (a hand-edited
   `"timeout_ms": -1` became `(DWORD)0xFFFFFFFF` ≈ 49 days inside `IcmpSendEcho`,
   on a thread that shutdown then joins forever).

   Both follow-ups are now fixed too: `pmx_tcp_connect` spends its timeout as a
   **total budget across every resolved address** (a name with a dozen blackholed
   A/AAAA records used to take N × timeout), and `pmx_checker_destroy`
   **abandons** queued jobs instead of draining them (queueing checks against
   unreachable hosts and then quitting used to freeze the GUI thread for the
   whole backlog). An in-flight check still has to finish, but it is now bounded
   by a real deadline rather than by the size of the queue.

7. **Host-NAME rules do not match on the WinDivert backend — they silently never
   fire.** ⚠️ This one is unfixed and matters. `wd_pump` fills `dst_host` from
   `WinDivertHelperFormatIPv4Address` / `...IPv6Address`, i.e. **always a numeric
   IP literal**, and `pmx_rule_matches` globs `host_pattern` against exactly that
   string. So a rule like `*.doubleclick.net` (Block) or `*.example.com` (Proxy)
   can never match real traffic: the app resolves the name itself and connects to
   `142.250.185.10`, the rule falls through, and the connection takes the default
   action. The Connections view shows it as an ordinary Direct/Default row, so
   nothing looks wrong. The rules panel's own placeholder text (`*.example.com;10.*`)
   actively teaches the pattern that doesn't work.

   Consequences today: numeric host patterns (`10.*`, `127.*`, `192.168.*`) work;
   names do not. In the seeded "Local & LAN direct" rule, the `localhost` and
   `*.local` segments are dead while the three numeric ones work.

   **It is no longer silent (2026-07-25).** The limitation itself is unchanged —
   the real fix needs name capture, which is a feature, not a patch — but it can
   no longer bite you without saying so:
   - `pmx_backend_caps.host_names` records whether a backend can ever put a NAME
     in `dst_host`. The stub sets it **true** (it fabricates named demo traffic —
     which is precisely why this went unnoticed: every test ran against the stub,
     where name rules work perfectly). The WinDivert backend sets it **false**.
   - `pmx_host_pattern_needs_names()` flags a pattern that only a name can
     satisfy (`*.example.com` yes; `10.*`, `fe80::*`, `*` no).
   - The rules editor shows a warning on such a rule while the active backend
     can't honour it, and `pmx_engine_start` logs a `WARN` naming every enabled
     rule that will never match.
   - The seeded "Local & LAN direct" rule dropped its dead `localhost`/`*.local`
     segments for numeric ones, and a test asserts the shipped profile never
     relies on names again.

   Until name capture lands, **write host rules as IP globs**. A name-based rule
   is documentation, not enforcement — and now the app tells you so.

8. **An invalid port spec is not enforced consistently.** The rules editor only
   *warns* about a spec that fails `pmx_port_spec_validate` — it still stores it,
   and `pmx_port_spec_match` then parses it leniently. The common typo
   `8000 - 8080` was the dangerous case (it matched only the two endpoints, so a
   Block rule missed everything between); that now parses as a proper range.
   Still open: a spec the validator rejects outright, e.g. `-1-70000`, is treated
   by `match` as 0-65535 — a Direct rule with that spec matches every port and
   shadows every Proxy/Block rule under it. `pmx_profile_validate` reports such
   specs, but nothing forces the user to fix one. The clean fix is to refuse to
   store an invalid spec, or to skip-and-loudly-log such a rule in the engine.

9. **OpenVPN's management socket has no password. ⚠️ Unfixed, deliberately.**
   ProxiMight starts `openvpn.exe --management 127.0.0.1 <port>` so it can ask
   whether the tunnel actually came up rather than assuming it did. With no
   `pwfile` argument that interface is **fully privileged for anyone who can open
   a TCP connection to it**, and the port is deterministic (25340 + slot). Any
   unprivileged local process can connect and issue `state` (read your tunnel's
   assigned IP and remote) or `signal SIGTERM` (**tear the tunnel down**). For a
   tool whose whole promise is that traffic stays inside the tunnel, a local
   unauthenticated kill is a real weakness.

   **Why it is still here:** the fix (generate a random secret, write it to a
   pwfile, pass it to `--management`, send it as the first line on connect, and
   delete it on teardown) changes the command line on the *one path that is known
   to work* — and it cannot be verified without standing up a real VPN server.
   Shipping an unverified change that could stop tunnels from starting at all was
   judged worse than the exposure. **If you can test against a real endpoint,
   this is the highest-value thing to fix next.** Mitigation meanwhile: the
   exposure requires code already running as your user on your machine.

11. **Saving a profile can no longer destroy it.** `write_file_atomic` used to
    `remove()` the target and then `rename()` the temp over it, leaving a window
    with no profile at all — and if the rename failed (on Windows a sharing
    violation from an AV scanner or the search indexer briefly holding the temp
    is a real occurrence) it deleted the temp too and **both** files were gone.
    That was survivable while saving was explicit, but became a live data-loss
    path the moment `pmx_profile_load` started rewriting the file to migrate
    legacy plaintext: merely opening the app could destroy the profile. It now
    uses `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)` on Windows and plain
    `rename()` elsewhere — both replace in one step, so a failure leaves the
    original intact, and the temp is kept rather than deleted.

10. **The connection log can drop rows under extreme load.** The engine's flow
    inbox is now capped (4096) instead of unbounded — a connect storm while the
    frame loop is stalled (dragging the window puts Win32 in a modal loop) could
    otherwise grow it without limit, ~92 MB for one full-range port scan. Dropped
    flows are counted in `pmx_engine_status.flows_dropped`. **This never changes
    a verdict**: a backend that must gate a connection calls
    `pmx_engine_decide()` inline, not through this queue. It only means the
    displayed log is incomplete, and it says so rather than pretending.

12. **"Fail to backup" and redundancy failover are names without mechanisms.**
    Nothing in the tree promotes a backup proxy. `PMX_LOCKDOWN_FAIL_BACKUP`
    engages the firewall exactly like `PMX_LOCKDOWN_FAIL_CLOSED` and then reports
    the state as "Failing over"; a *redundancy* chain resolves to hop 0 without
    ever asking the checker whether that hop is reachable. **Neither leaks** —
    both end in a block, which is the safe direction — but a user who picks "fail
    to backup" expecting continuity gets a kill switch instead. The mode's
    description in the Lockdown panel now says this outright, and
    `pmx_chain.h` / `pmx_lockdown.h` carry the same warning at the point of
    definition. Making it real means feeding `pmx_checker` health into
    `pmx_engine`'s resolve step, and it must keep failing closed when every
    alternative is down.

13. **The redirect layer's byte-order assumption cannot be settled by reading.**
    The WinDivert SOCKET layer fills the NAT table (`addr.Socket.RemoteAddr`,
    `RemotePort`, used without `ntoh*`), and the NETWORK layer compares against
    packet-header fields (used with `ntoh*`). Those two are *self*-consistent,
    which is exactly what makes the question undecidable on paper: "both ends
    right" and "both ends wrong" look identical in the source. If they are wrong,
    every `PROXY` verdict registers successfully, logs `redirecting … via`, and
    then egresses **direct** — a total silent leak that reads as success.

    One elevated wire test settles it. Run with `--log=debug` and watch: if
    `redirecting` is logged while `n_redirected` stays at 0, the NAT key is
    byte-swapped. The rewrite path also now logs `sport N matches a mapping for a
    different destination; not rewriting` whenever a source-port hit fails the
    destination check, which is the same symptom seen from the other side.

## VPN configs — a deliberate exception to the plaintext problem

Proxy passwords live *inside* the profile, which is sealed at rest on Windows and
still plaintext on any platform without a provider (issue 1 above). VPN configs
are **not** handled that way at all, because they carry far more dangerous
material — a WireGuard `PrivateKey` or an OpenVPN inline `<key>` is the whole
identity of the tunnel — and a seal that only covers one platform is not a good
enough home for it.

So `pmx_vpn` records only that a secret is **present** (`has_private_key`,
`has_preshared_key`, `has_inline_secrets`) plus non-secret metadata (endpoints,
AllowedIPs, cipher, MTU). The key material is never copied into memory or into
`profile.pmxprofile`; the original config file stays where you put it, and its
path is what gets handed to the OpenVPN/WireGuard client. `test_vpn` scans the
raw bytes of the parsed struct to prove no secret leaked into it.

**If you extend the VPN model, do not add a field that holds key material.**
That would turn a known wart into a serious problem.

A related hazard the parser handles: text inside an inline block is never
interpreted as configuration. A certificate body containing the line
`remote evil.example.com 1234` must not add a tunnel endpoint — that would be
config injection with real consequences (traffic sent somewhere you never
chose). There is a test for exactly that.

**This defence was too narrow until 2026-07-24 and has been widened.** It used to
allowlist ten known tags (`ca`, `cert`, `dh`, `key`, `tls-auth`, …) and parse the
body of *every other* `<tag>` block as configuration. OpenVPN treats **any**
`<tag>…</tag>` as an inline file, so a `remote` line hidden inside a block we
didn't recognize — `<auth-user-pass>`, `<crl-verify>`, `<peer-fingerprint>`,
`<http-proxy-user-pass>` — was injected as a real tunnel endpoint. That is worse
than it first sounds: `pmx_engine` copies every parsed VPN endpoint into the
**lockdown allowlist**, so a hostile `.ovpn` could punch an attacker-chosen
host:port hole straight through the kill switch. The old test passed only because
it happened to use `<ca>`.

The parser now **skips every inline block by default** and matches tags
**case-sensitively**, like OpenVPN. A stray `</CA>` no longer ends a `<ca>` block
early (which previously resumed parsing at a point OpenVPN still treats as
certificate data), and the one parsed exception — lowercase `<connection>`, whose
body really is configuration — is matched exactly.

That last part was a **follow-up fix**, and it is a good illustration of how
these holes hide: the exception was originally matched case-*insensitively*, so
`<Connection>` still had its body parsed as configuration even though OpenVPN
treats it as an unrecognized inline file. The injection route was closed in one
spelling and left open in another. `test_vpn` now covers four unrecognized-tag
injections, the mis-cased close, and three case variants of `<connection>`.

**Not defended, and worth knowing:** an imported `.ovpn` can still carry
`script-security 2` plus `up <command>`, which **openvpn.exe itself** will
execute. ProxiMight neither strips nor surfaces those directives, and the parsed
summary shown in the UI does not mention them — so treat a `.ovpn` from an
untrusted source as you would any executable script.

## Network path diagnostics leak differently

ICMP ping and the MTR path scan go out **from this machine, unproxied** — they
cannot travel through a SOCKS/HTTP proxy. They reveal your IP to the target and
to every router on the way, exactly like the system `ping`/`tracert`. The UI
says so, so a clean-looking hop list is never mistaken for proof that your
proxied traffic is private.

## Secrets handling in code

- Passwords are **never written to the log**. The logger takes formatted lines;
  callers never pass credentials to `pmx_log*`. Proxy hosts/ports/labels are
  fine to log; credentials are not.
- Proxy handshakes send credentials only to the configured proxy endpoint over
  the socket — they are not echoed into error messages.
- If you add code that could surface a request/response body in an error, mask
  secret fields first (mirror the discipline used elsewhere in the project).

## Regression-test coverage of the fixes above

The CHANGELOG used to claim every security fix carried a regression test. That was
not true, and the shape of the gap matters more than the count — so here it is
plainly.

**Covered by the unit suite** (portable C, no driver, no GUI): the NAT table's
fail-closed-when-full, closed-but-still-matching, and inactivity-based expiry
semantics (`test_nat`); the lockdown state machine including mode changes while
armed, an unrecognized mode, and an `engage()` that fails (`test_chain_failover`);
`.ovpn` config injection and the no-secret-bytes guarantee (`test_vpn`); the
sealed-container round-trip, tamper rejection and legacy migration
(`test_protect`); whole-operation socket deadlines and the relay refusing
unregistered connections (`test_relay`, `test_relay_chain`); the profile's atomic
save (`test_profile_json`); child-process capture above 4 KB (`test_proc`).

**Not covered, and not coverable by this suite:**

- Anything inside `backend_windivert.c` — the UDP fail-closed guard, the
  self-exclusion by PID, and the destination check on the outbound rewrite. All
  three need a live WinDivert handle and Administrator, so they are verified by
  reading and will only be *observed* during the wire test in
  `docs/SETUP-WINDIVERT.md`.
- Anything in the GUI. The collapsed-input and off-screen-button defects were
  found by screenshotting the running app and neither the compiler nor CTest can
  see them; the project's habit of screenshotting after GUI changes is the
  substitute, and it is not automated.
- The real firewall, because there isn't one yet (issue 2).

Two cheap wins nobody has taken: ASan/UBSan over the existing 14 suites, and a
fuzz harness on the six pure parsers that consume bytes from a proxy, a config
file, or a subprocess (`pmx_socks5_parse_connect_reply`,
`pmx_http_parse_connect_reply`, `pmx_vpn_parse_ovpn`, `pmx_vpn_parse_wg`,
`pmx_wg_parse_dump`, `pmx_ovpn_parse_state`). They are I/O-free, so a harness is
about twenty lines each, and `test_socks` currently has no negative cases at all.

## Privilege

- The stub backend and stub firewall need **no elevation**.
- Real redirection (WinDivert/WFP, pf) will require **Administrator / root**.
  When that lands, elevation should be requested only at arm time, and the
  enforcement must **fail safe** (a crash must not leave the machine in a
  half-blocked or silently-leaking state — WFP dynamic filters and a pf-anchor
  watchdog both auto-clean).

## Reporting

This is early software. If you find a leak path or a credential-handling bug,
treat it as important — in a tool like this, a leak is the whole ballgame.

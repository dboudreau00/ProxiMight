# Architecture

ProxiMight is split into a **portable C engine** (`proximight_core`) and a
**Dear ImGui front-end** (`proximight`). Any other front-end (a CLI, a service)
can link the engine directly.

## Layers

```
src/gui/     Dear ImGui (cimgui) front-end
  gui_backend.cpp   C++ shim: GLFW window, GL context, imgui backends, fonts,
                    and stable-C drawing wrappers (guix_*)
  gui_app.c         app state, sidebar, top bar, theme, delete-confirm modal
  gui_theme.c       light/dark palettes -> imgui style
  gui_icons.c       vector icons (chain-link mark, shield, gear, ...)
  gui_widgets.c     buttons, toggle, badges, cards, notes, form inputs
  panels/*.c        one file per section (dashboard, proxies, rules, ...)

src/core/    Portable C engine (no UI, no platform-UI deps)
  pmx_engine.c      orchestrator: resolve flows, record events, run lockdown
  pmx_profile.c     data model + JSON persistence (cJSON)
  pmx_rule.c        glob/port matching + rule evaluation
  pmx_chain.c       chain hop management
  pmx_proxy.c       proxy handshakes dispatch
  pmx_socks.c       SOCKS4/4a/5 encoders/parsers (pure, testable)
  pmx_http_connect.c HTTP CONNECT + base64 (pure, testable)
  pmx_checker.c     sync + threaded async proxy health checks
  pmx_lockdown.c    kill-switch state machine + stub firewall
  pmx_procinfo.c    connection -> owning PID -> image name (Windows)
  pmx_netpath.c     ICMP ping + MTR-style per-hop path analysis
  pmx_vpn.c         OpenVPN/WireGuard config ingestion (never stores secrets)
  pmx_relay.c       local SOCKSifier that carries redirected connections
  pmx_nat.c         src_port -> original destination, for the packet rewrite
  pmx_proc.c        run/spawn external programs (the VPN clients)
  pmx_vpn_run.c     tunnel bring-up, tear-down and handshake verification
  pmx_net.c         cross-platform blocking sockets + monotonic clock
  pmx_thread.c      Win32/pthread threads, mutex, condvar
  pmx_log.c         thread-safe leveled logging with a pluggable sink

src/backend/ Pluggable redirection + firewall backends
  backend_stub.c            default; demo-traffic generator; platform factory
  windows/backend_windivert.c   WinDivert scaffold (gated: PMX_HAVE_WINDIVERT)
  windows/firewall_wfp.c        WFP scaffold        (gated: PMX_HAVE_WFP)
  macos/backend_pf.c            pf/utun scaffold    (gated: PMX_HAVE_PF_BACKEND)
  macos/firewall_pf.c           pf scaffold         (gated: PMX_HAVE_PF_FIREWALL)
```

## The redirection contract (`pmx_backend`)

A backend observes new outbound connections ("flows"), reports each to the
engine via a callback, and enforces the engine's decision:

```c
struct pmx_backend {
    const char *name;
    pmx_backend_caps caps;         // per_app, can_block, killswitch, real
    pmx_status (*start)(...);
    pmx_status (*stop)(...);
    bool       (*is_active)(...);
    void       (*set_flow_cb)(..., pmx_flow_cb cb, void *user);
    pmx_status (*apply_decision)(..., const pmx_flow*, const pmx_decision*);
    void       (*destroy)(...);
};
```

The **stub backend** fabricates plausible flows on a timer (`caps.real=false`)
so the whole pipeline — rule resolution → decision → connection log → lockdown
watcher — is live without touching the OS. Real backends implement the same
vtable; `pmx_backend_platform_create()` returns the best available, falling back
to the stub.

## Threading model (deliberately simple)

- The **backend** runs on its own thread and pushes flows into the engine's
  mutex-guarded **inbox**.
- **`pmx_engine_pump()`** (called once per GUI frame) drains the inbox, resolves
  each flow against the profile, records an event, and calls `apply_decision`.
  All profile access happens on this one thread — so **the profile needs no
  locks**.
- The **checker** owns a worker thread for network probes and returns results
  through its own queue, which the engine/GUI poll.
- The **log sink** may be called from any thread, so the GUI's log ring is
  mutex-guarded.

### Inline verdicts without losing that simplicity

A real redirection backend can't wait for the next pump — it must allow, block,
or divert a connection the instant the OS reports it, on its own thread. That
would normally force locks around the live profile.

Instead the engine publishes a **snapshot**: `pmx_engine_pump()` deep-copies the
profile into `engine->snap` under a small mutex, and `pmx_engine_decide()`
resolves against that snapshot from any thread. Backends receive it through the
optional `set_decide_cb` hook. Consequences worth knowing:

- The live profile stays single-threaded and lock-free (GUI edits need no locks).
- Edits take effect for backends on the **next pump** — one frame of lag, which
  is irrelevant for a rule change and is pinned down by
  `tests/test_decide_snapshot.c`.
- Profiles are small, so copying once per frame is cheaper and far less
  error-prone than trying to track every in-place edit the GUI makes.

### The relay

`pmx_relay` is the other half of redirection. The redirect layer registers
"source port X was really headed to host:port, via this proxy", then NATs the
connection to the relay's loopback listener. On accept, the relay matches the
peer's source port, performs `pmx_proxy_handshake()` to the real destination
through the chosen proxy, and splices bytes. Unmatched connections are dropped,
so it can never act as an open proxy. It is driver-independent and tested
standalone (`tests/test_relay.c`).

## Rule resolution (the heart)

`pmx_resolve_with_profile()` is a pure function: walk rules top-to-bottom, take
the first *enabled* rule whose (app, host, port) criteria all match, else the
default rule; produce a `pmx_decision` (verdict + target proxy/chain + which
rule decided). It is unit-tested independently of any backend.

## Extending it

- **A new proxy protocol:** add encoders to `pmx_socks.c`/`pmx_http_connect.c`
  and a case in `pmx_proxy_handshake()`.
- **A real redirection backend:** implement the `pmx_backend` vtable in a new
  file; return it from `pmx_backend_platform_create()` behind a build gate.
- **A real firewall:** implement the `pmx_firewall` vtable; return it from
  `pmx_firewall_platform_create()`.
- **A new GUI section:** add a `gui_nav` entry + a `panel_*.c` and wire it into
  `gui_app.c`'s dispatch.

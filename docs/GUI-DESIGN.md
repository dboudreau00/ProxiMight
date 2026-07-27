# GUI design notes

The front-end is Dear ImGui driven entirely from C (via cimgui), with a thin
C++ shim (`gui_backend.cpp`) that owns the window and exposes stable-C drawing
primitives. The goal is a tool that feels considered — not a debug panel.

## Design language

- **Chain-link as the motif.** The brand mark is two interlocked links drawn
  with the draw list (`guix_draw_chain_mark`), reused at small sizes as the
  `Chains` nav icon. It also seeds the icon vocabulary: single links, routes,
  shackled locks.
- **"Quiet steel" palette.** Layered graphite surfaces with a single
  chain-steel-blue accent used sparingly for the active state, primary actions,
  and the proxy verdict. Semantic green/amber/red for direct/failover/blocked.
- **Two themes, both first-class.** `gui_theme_dark()` / `gui_theme_light()`
  define the same named roles; `gui_theme_apply()` starts from imgui's built-in
  base (so version-specific slots stay sane) then overrides the long-stable
  color slots. Toggle in Settings.
- **DPI-aware.** Everything scales by the monitor content scale; a native system
  font (Segoe UI / SF / DejaVu) is loaded for crisp text, with a heavier weight
  for headings.

## Structure

- A single full-viewport root window, no imgui title chrome — the OS title bar
  is the only chrome.
- **Left sidebar:** brand block, nav (Dashboard, Proxy servers, Rules, Chains,
  Connections, Proxy checker, Lockdown, Settings), and a pinned bottom control
  block (Start/Stop + engine & lockdown status pills).
- **Content area:** a section title bar (with Save) and the active panel.

## Widgets (`gui_widgets.c`)

Custom-drawn for full control of the aesthetic:

- **Buttons** (`primary`/`secondary`/`ghost`/`danger`) — icon + label, drawn via
  an invisible button + `guix` fill/stroke so hover/active states and rounding
  are exact.
- **Toggle** — an iOS-style switch.
- **Cards** — bordered, auto-height (`ImGuiChildFlags_AutoResizeY`) surfaces.
- **Notes/banners** — tinted, left-accent-barred callouts (used for the honest
  "simulated backend" and safety warnings).
- **Stat tiles, status pills, badges, section headers, form inputs.**

## Interaction highlights

- **Drag-to-reorder rules** — the grip cell in the rules table is an imgui
  drag-drop source/target carrying the row index; on drop the profile calls
  `pmx_profile_move_rule`. Up/Down buttons in the editor are the accessible
  fallback.
- **Master-detail** editors for proxies, rules, and chains.
- **Live everything** — with the stub backend's demo traffic on, the Dashboard
  counters, Connections table, and Lockdown watcher all move in real time,
  because the GUI pumps the engine once per frame.

## The `guix_*` shim boundary

cimgui's ABI for by-value returns (e.g. `GetContentRegionAvail`) and some enums
have drifted across imgui versions. To stay robust, all geometry getters and all
`ImDrawList` drawing go through thin C wrappers implemented in the C++ shim
(`guix_content_avail`, `guix_draw_rect`, `guix_draw_chain_mark`, …). The C UI
code never touches raw imgui draw calls, so the custom artwork is insulated from
version churn. (This is exactly what let the build survive imgui 1.92's
`AddRect` parameter-order change and `PushFont` signature change — the fixes were
confined to the shim.)

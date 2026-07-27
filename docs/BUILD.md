# Building ProxiMight

## Requirements

- A **C / C++17 toolchain**.
  - **Windows:** Visual Studio 2022 with the **"Desktop development with C++"**
    workload (this brings MSVC `cl`, the Windows SDK, and the VS-bundled CMake +
    Ninja). Nothing needs to be on `PATH` — the build script activates the VS
    developer environment for you.
  - **macOS:** Xcode command-line tools + CMake ≥ 3.24 (`brew install cmake ninja`).
- **Internet on the first configure** — CMake fetches GLFW, cimgui (with its
  bundled imgui submodule), and cJSON via FetchContent. After that they are
  cached under `build/<preset>/_deps`.

Verified building on Windows against **MSVC 19.44** and **Dear ImGui 1.92**
(cimgui `master`).

## Windows — the easy way

```bash
tools/build.ps1
```

This finds Visual Studio via `vswhere`, enters its developer shell, configures
the `windows-debug` preset with the VS-bundled CMake + Ninja, and builds. Then:

```bash
tools/run.ps1
```

Options:

```bash
tools/build.ps1 -Preset windows-release   # optimized (also hides the console)
tools/build.ps1 -Clean                     # wipe the build dir first
```

## Windows — manual (from a *Developer PowerShell for VS 2022*)

```bash
cmake --preset windows-debug
cmake --build --preset windows-debug
ctest --preset windows-debug
```

The binary lands at `build/windows-debug/bin/proximight.exe`.

## macOS

```bash
cmake --preset macos-debug
cmake --build --preset macos-debug
ctest --preset macos-debug
```

## Handy runtime flags

Open straight to a panel (useful when iterating on one screen, or for
screenshot/regression checks):

```bash
proximight.exe --panel=settings
```

Valid names: `dashboard`, `proxies`, `rules`, `chains`, `connections`,
`checker`, `lockdown`, `settings`.

Start the engine immediately (handy for watching the pipeline run without
clicking, e.g. for screenshots or a smoke test):

```bash
proximight.exe --panel=connections --autostart
```

Other flags: `--import-vpn=<path>` imports an `.ovpn`/`.conf` at startup,
`--trace=<host>` kicks off a network-path scan, and `--backend=platform`
switches to the real WinDivert backend (needs Administrator).

## What gets built

- `proximight_core` — static engine library.
- `cimgui` — static lib of imgui core + the C bindings.
- `proximight` — the app executable (links core + cimgui + glfw + OpenGL).
- `test_socks`, `test_profile_json`, `test_rules`, `test_chain_failover` — CTest
  unit tests (they always build and run; no network needed).

## Enabling the real platform backends (later)

The platform redirection/firewall backends compile to safe no-ops until you
supply their SDKs and flip a build gate. For Windows + WinDivert, drop the SDK
under `third_party/windivert/`, then in `src/core/CMakeLists.txt`:

```cmake
target_compile_definitions(proximight_core PRIVATE PMX_HAVE_WINDIVERT)
target_link_libraries(proximight_core PRIVATE WinDivert)
```

Equivalent gates exist for WFP (`PMX_HAVE_WFP`), pf backend
(`PMX_HAVE_PF_BACKEND`), and pf firewall (`PMX_HAVE_PF_FIREWALL`).

## Data & log locations

- **Windows:** `%APPDATA%\ProxiMight\` → `profile.pmxprofile`, `logs\proximight.log`
- **macOS/Linux:** `~/.config/proximight/`

## Troubleshooting

- *"vswhere.exe is not recognized"* printed during activation is harmless — the
  script still finds the toolchain (you'll see the resolved `cmake`/`ninja`/`cl`
  paths right after).
- *First configure fails to fetch deps* — you're offline; connect and retry.
- *`ninja: error: Stat(...): Filename longer than 260 characters`* during the
  `cimgui` populate step — your checkout is too deep, not broken. FetchContent
  builds each dependency in a sub-project whose stamp paths add roughly 130
  characters (`build/<preset>/_deps/cimgui-subbuild/cimgui-populate-prefix/src/
  cimgui-populate-stamp/...`), and Windows' legacy `MAX_PATH` is 260. Clone
  somewhere shorter — `C:\src\ProxiMight` always works — or enable long paths
  (`git config --system core.longpaths true`, plus the `LongPathsEnabled` policy).
  Nested OneDrive or `Downloads` folders are the usual culprits.
- *No window appears* — check `logs\proximight.log`; the debug build also prints
  to the console.

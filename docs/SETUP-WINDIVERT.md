# Enabling real per-app monitoring (WinDivert)

ProxiMight can watch **real outbound connections with the owning application**
on Windows. That needs the **WinDivert** driver, which ProxiMight deliberately
**does not bundle**.

## Why we don't ship it

WinDivert is a kernel driver. Bundling someone else's signed driver inside a
network tool breaks your ability to verify the trust chain yourself — you should
download it from the upstream project, check it, and install it knowingly. It
also carries its own license (**LGPLv3 / GPLv3 dual**), which has redistribution
consequences for anyone shipping a ProxiMight binary. Get your own copy.

## 1. Download

Upstream project: **https://github.com/basil00/WinDivert** (releases), mirrored
at `https://reqrypt.org/windivert.html`. Grab the **WinDivert 2.2.x x64** zip.

## 2. Verify it

- Compare the archive's SHA-256 against the value published on the release page.
- After extracting, confirm the binaries are **digitally signed**:

```bash
Get-AuthenticodeSignature .\WinDivert.dll, .\WinDivert64.sys | Format-List Status, SignerCertificate
```

`Status` must be `Valid`. If it isn't, stop — do not load it.

## 3. Put it where CMake looks

CMake looks in `third_party/windivert/` by default. Four files matter — the
header, the import library, the DLL and the **x64** driver:

| File | What it is |
|---|---|
| `windivert.h` | header, compiled against |
| `WinDivert.lib` | import library, linked |
| `WinDivert.dll` | user-space library, loaded at run time |
| `WinDivert64.sys` | the kernel driver itself, x64 |

**The simplest thing that works** — flatten all four into one folder:

```
ProxiMight/
  third_party/
    windivert/
      windivert.h
      WinDivert.lib
      WinDivert.dll
      WinDivert64.sys
```

**Or drop the extracted release in unchanged** — the official zip's own layout is
recognised as-is:

```
ProxiMight/
  third_party/
    windivert/
      include/windivert.h
      x64/WinDivert.lib
      x64/WinDivert.dll
      x64/WinDivert64.sys
```

Keeping it elsewhere? Point CMake at the **extracted root** — the folder that
*contains* `include/` and `x64/`:

```bash
cmake --preset windows-debug -DPMX_WINDIVERT_DIR="C:/path/to/WinDivert-2.2.2-A"
```

> Earlier revisions of this page pointed that example at `.../x64`. That finds
> `WinDivert.lib` but not `windivert.h`, so detection half-succeeded and the build
> fell back to the stub backend with no obvious reason why. Both spellings work
> now, and CMake says which half it is missing if only one turns up.

Whichever layout you use, the build **stages `WinDivert.dll` and `WinDivert64.sys`
next to the executable** for you — the driver has to sit beside the binary that
opens it.

## 4. Re-run the build

```bash
tools/build.ps1 -Clean
```

You should see in the configure output:

```
WinDivert SDK found -> real per-app monitoring enabled
  staged WinDivert.dll next to the executable
```

If you instead see *"WinDivert SDK not found"*, the headers/lib weren't where
CMake looked — check step 3.

## 5. Run it as Administrator

The driver only loads with elevation:

```bash
Start-Process .\build\windows-debug\bin\proximight.exe -Verb RunAs
```

Then in **Settings → Redirection backend**, switch to the platform backend and
press **Start**. The **Connections** panel will fill with real applications and
the destinations they're reaching, each classified by your rules.

## What this does — and does not — do

- ✅ **Real per-application monitoring.** The socket layer hands us the owning
  PID directly, so attribution is exact and every connection is evaluated
  against your rules.
- ✅ **Real blocking.** A `Block` rule drops the connect; the app sees it fail.
- 🔶 **Proxy redirection is implemented but unproven on the wire.** The rewrite
  (NAT the flow to the local relay and back) is written and compiles, and its
  moving parts are unit tested — but nobody has yet confirmed Windows accepts
  the rewritten packets on a live machine. Treat this run as the experiment.
- ❌ **Multi-hop chains and IPv6 are refused, not approximated.** A chain is
  never quietly proxied through only its first hop.

## The wire test — proving the packet rewrite

This is the **one experiment** standing between ProxiMight and being a real
proxifier. Everything it depends on is built, unit-tested and reviewed; what has
never been observed is whether Windows accepts the rewritten loopback packets on
a live machine. Until someone runs this, `caps.real` stays `false`.

### What you are trying to observe

A proxied connection has to survive four hops. The test succeeds only if **all
four** happen for the same flow:

| # | Stage | Evidence |
|---|---|---|
| 1 | The socket layer sees the connect and resolves `PROXY` | `redirecting <app> -> <host>:<port> via '<proxy>'` |
| 2 | Relay + NAT registration succeed, SYN allowed out | (no "cannot be redirected" line for that flow) |
| 3 | The network layer rewrites it to loopback and the relay completes the proxy handshake | `[relay] <host>:<port> established through 1 hop(s)` |
| 4 | Real bytes come back | your test command prints a real response |

**Lines 1 and 3 are logged at DEBUG**, so you must pass `--log=debug` or you will
see nothing and conclude, wrongly, that it failed.

### Safety first

Two facts bound the blast radius: closing ProxiMight (or the process dying) tears
down the WinDivert handles and traffic returns to normal **immediately**, and
`Stop` does the same. The real hazard is not permanence, it is scope — a
non-sniff socket handle gates **every** outbound TCP/UDP connect on the machine
while it is open.

So set up for a boring mistake:

1. **Have a real, reachable proxy** and confirm it **green in the Proxy checker**
   before you touch the backend. A proxy that does not work turns step 2 into a
   `BLOCKED` line for every matching flow.
2. **Disable the seeded "Browsers via Tor" rule** (or point it at your working
   proxy). It is a `Proxy` rule aimed at `127.0.0.1:9050`; with no Tor running it
   fails closed and blocks your browsers.
3. **Scope your test rule to one throwaway app** — `curl.exe` — and leave the
   default rule on `Direct`. Do *not* start with a rule matching your browser.
4. **Use an IP, not a hostname, in the rule's host field** (or leave it blank and
   match on the app). The backend reports numeric addresses only, so a host-NAME
   pattern can never match — the app warns about this now, but it is the most
   common way to conclude "redirection is broken" when the rule simply never
   fired.
5. Keep a second, non-elevated terminal open. If the GUI becomes unresponsive
   while holding the handle, `Stop-Process -Name proximight -Force` from there
   restores connectivity instantly.

### Run it

```bash
Start-Process .\build\windows-release\bin\proximight.exe -Verb RunAs -ArgumentList "--backend=platform","--panel=connections","--log=debug"
```

Press **Start**. You should immediately see:

```
[relay] listening on 127.0.0.1:<port>
[backend:windivert] ENFORCING: real connections are now gated by your rules
```

Then, from an ordinary prompt, exercise **only** the test app:

```bash
curl.exe -sS -o NUL -w "%{http_code}\n" http://example.com
```

### Reading the result

**Success** looks like this in `%APPDATA%\ProxiMight\logs\proximight.log`:

```
[backend:windivert] redirecting curl.exe -> 93.184.216.34:80 via 'My proxy' (1 hop(s))
[relay] 93.184.216.34:80 established through 1 hop(s), first 'My proxy'
```

plus `curl` printing `200`. On **Stop**, the summary line reports how many
packets were actually rewritten:

```
[backend:windivert] stopped (N allowed, N blocked, N packets redirected)
```

A non-zero **packets redirected** with a successful `curl` is the result that
justifies flipping `caps.real`.

**Independent confirmation** (worth doing — it rules out "it worked but went
direct"): compare what the far end sees.

```bash
curl.exe -sS https://api.ipify.org        # through the rule -> should be the PROXY's IP
```

If that returns your own IP, the flow went direct and the rewrite did **not**
work, regardless of what the log says.

### Failure modes and what they mean

| What you see | Meaning |
|---|---|
| `access denied — must run as Administrator` | Not elevated. |
| No `redirecting` line at all | The rule never matched. Check the app name, and that you did not use a host **name** pattern. |
| `cannot be redirected (no usable proxy resolved)` | The rule's target proxy is missing or disabled. |
| `... — BLOCKING (fail closed)` | Working as designed: it refused to leak rather than send unproxied. Fix the proxy. |
| `[relay] no destination registered for source port N` | The network layer redirected a flow the socket layer never registered — a genuine bug worth reporting. |
| `redirecting` appears but no `established` | The rewrite reached the relay but the proxy handshake failed — check the proxy, then the checker. |
| `redirecting` + `established` but curl hangs | The reply path is not being rewritten back. **This is the interesting failure** — it is what the experiment is really testing. |
| `WinDivert service failed to start … the system cannot find the file specified` (in Event Viewer → System), even though the `.sys` is present | The kernel is **refusing to load the driver**, not literally missing it. See below. |

### The driver won't load at all (Memory Integrity / driver blocklist)

On a modern Windows 11 machine the most likely wall you hit is not a ProxiMight
bug — it is Windows refusing to load WinDivert. WinDivert is on Microsoft's
**vulnerable-driver blocklist** (malware abused it), and **Memory Integrity**
(Core isolation / HVCI) blocks exactly this class of driver. Symptoms:

- ProxiMight logs `WinDivertOpen failed (error 2)` — with the improved messages,
  it will say the driver was *rejected*, not that files are missing.
- Event Viewer → *Windows Logs → System* shows `Service Control Manager` event
  **7000**: *"The WinDivert service failed to start … The system cannot find the
  file specified"* — with the `.sys` sitting right there beside the exe.

Confirm the posture (PowerShell):

```bash
(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning   # 2 = Memory Integrity on
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config').VulnerableDriverBlocklistEnable                  # 1 = blocklist on
```

To run the experiment you have to relax that, which is a **real, deliberate
security downgrade** — WinDivert is blocklisted for a reason:

1. *Settings → Privacy & security → Windows Security → Device security → Core
   isolation → **Memory integrity: Off***, then **reboot**.
2. If it still fails, the vulnerable-driver blocklist is also blocking it; that
   is harder to disable and tied to Smart App Control on Win11.
3. Run the test, then **turn Memory Integrity back on**.

The cleaner alternative is a throwaway **VM without Core isolation**. And note
the implication: many of your *users* will have Memory Integrity on too, so real
redirection may simply be unavailable to them without the same trade-off. That
is part of why this backend is honestly labelled unproven.

### If it works

Flip `caps.real` to `true` in `src/backend/windows/backend_windivert.c` (one
line, next to `caps.can_block`), rebuild, and the "not redirecting real traffic"
banner retires itself. Record what you actually saw — in `CHANGELOG.md` and in
the "Known issues" list of `docs/PRIVACY-SECURITY.md` — because the value of
those documents is that every claim in them is backed by an observation.

If anything looks wrong at any point, press **Stop** or close the window. That is
the entire recovery procedure.

## Uninstalling

Stop ProxiMight, delete the staged `WinDivert.dll` / `WinDivert64.sys` next to
the executable and the files under `third_party/windivert`, then re-run CMake.
The build reverts to the stub backend. If the driver service was installed, it
can be removed with `sc.exe delete WinDivert` from an elevated prompt.

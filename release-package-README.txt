ProxiMight v0.2.0-alpha  —  self-contained Windows x64 build
============================================================

A per-application proxifier: force any app's traffic through the SOCKS/HTTP
proxies you choose, decided by rules you write, behind a fail-closed kill switch.

Run it:

    proximight.exe

That is the whole install. One file, no dependencies, no VC++ redistributable,
nothing to unpack. It writes its profile and log to:

    %APPDATA%\ProxiMight\


READ THIS FIRST — WHAT THIS BINARY CAN AND CANNOT DO
----------------------------------------------------

This build ships the SIMULATED backend only. It runs the complete rule, chain and
lockdown engine against generated traffic, so you can explore the entire interface
and design a working profile — but it does NOT see, redirect or block any real
connection on your machine.

That is deliberate, and it is a licensing decision rather than a technical one.
Real per-application interception needs the WinDivert SDK, which is a signed
KERNEL DRIVER under LGPLv3/GPLv3. Bundling it here would mean redistributing it,
and it would hand you a driver whose provenance you never checked. You should
obtain and signature-verify your own copy instead.


GETTING WINDIVERT — AND WHERE TO PUT IT
---------------------------------------

    Upstream : https://github.com/basil00/WinDivert
    Releases : https://github.com/basil00/WinDivert/releases
    Mirror   : https://reqrypt.org/windivert.html

Get the WinDivert 2.2.x **x64** zip. Verify it before you trust it: WinDivert
releases are signed, and the release page publishes hashes — check the one you
downloaded matches, on the vendor's page, over HTTPS.

>>> IMPORTANT: dropping WinDivert next to THIS executable does nothing. <<<

WinDivert support is a COMPILE-TIME decision. This binary was configured without
the SDK, so the driver code is not in it at all — `pmx_backend_windivert_create()`
is a stub that returns NULL, and choosing "Use platform backend" in Settings will
quietly hand you the simulated backend right back. No file you place beside
proximight.exe changes that. You have to rebuild from source.

So the rubric below is about the SOURCE TREE, not this folder.

  1. Clone the source somewhere SHORT — C:\src\ProxiMight. Windows' 260-character
     path limit bites during dependency fetch, and the error names ninja rather
     than the real cause.

  2. Put the SDK where CMake looks. Either layout is recognised:

     (a) Flattened — simplest:

         C:\src\ProxiMight\
           third_party\
             windivert\
               windivert.h
               WinDivert.lib
               WinDivert.dll
               WinDivert64.sys

     (b) The official zip, extracted unchanged:

         C:\src\ProxiMight\
           third_party\
             windivert\
               include\windivert.h
               x64\WinDivert.lib
               x64\WinDivert.dll
               x64\WinDivert64.sys

     Keeping it elsewhere? Point CMake at the EXTRACTED ROOT — the folder that
     contains include\ and x64\, NOT at x64 itself:

         cmake --preset windows-release -DPMX_WINDIVERT_DIR="C:/path/to/WinDivert-2.2.2-A"

     (third_party\ is gitignored in its entirety, so the driver can never be
     committed by accident.)

  3. Build. Confirm detection in the CMake output — this line must appear:

         -- WinDivert SDK found -> real per-app monitoring enabled

     If you instead see "not found", or a warning that it found the .lib but not
     windivert.h, the SDK is not where CMake looked. Note that CMake CACHES a
     failed search, so after moving files you must clear it:

         cmake --preset windows-release -U WINDIVERT_INCLUDE_DIR -U WINDIVERT_LIBRARY

  4. Run elevated. WinDivert loads a kernel driver; without Administrator you get
     ACCESS_DENIED. The build stages WinDivert.dll and WinDivert64.sys next to the
     executable automatically — the driver must sit beside the binary opening it.

Full procedure, including a low-risk way to test it on live traffic:
docs/SETUP-WINDIVERT.md

  ! On a current Windows 11 machine, Memory Integrity and the vulnerable-driver
    blocklist will refuse to load WinDivert at all. The real backend may be
    unavailable without relaxing that — a security trade-off to make knowingly,
    not by reflex.


WHAT YOU GET ONCE THE DRIVER IS IN
----------------------------------

Real per-application connections, attributed to the owning process, classified by
your rules live — and a Block rule genuinely drops the connect.

What is STILL unproven even then is REDIRECTION to a proxy. That path is written
and unit-tested, but no packet has ever been observed going through it, so
caps.real stays false and a Proxy verdict FAILS CLOSED rather than leaking out
unproxied. Lockdown likewise runs on a stub firewall that logs what it would block
instead of enforcing it.


STATUS
------

Unaudited pre-alpha. No independent security review has been done. If a traffic
leak would harm you, wait for a version that says otherwise.


USEFUL FLAGS
------------

    --panel=<name>    dashboard|proxies|rules|chains|vpn|connections|
                      checker|lockdown|settings
    --autostart       start the engine immediately
    --backend=platform  use the real backend (needs the SDK compiled in + admin)
    --log=<level>     trace|debug|info|warn|error|off   (default: info)
    --import-vpn=<p>  import a .ovpn / .conf at startup
    --trace=<host>    kick off an MTR path scan


WHAT IS IN THIS FOLDER
----------------------

    proximight.exe                  the application (static CRT, x64)
    LICENSE                         MIT, for ProxiMight's own code
    CHANGELOG.md                    what changed, and the known limitations
    RELEASE-NOTES.md                this release in detail
    docs/SETUP-WINDIVERT.md         obtaining, verifying and enabling the driver
    docs/PRIVACY-SECURITY.md        threat model and every known weakness
    docs/ROADMAP.md                 what works today and what is ahead


SOURCE
------

MIT licensed. The source is the real deliverable — this binary is a convenience
for looking at the interface without a toolchain.

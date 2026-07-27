# Security policy

## Supported versions

ProxiMight is **pre-alpha and unaudited**. Only the latest tag receives fixes,
and there is no stability guarantee. Do not deploy it where a leak would matter.

| Version | Supported |
|---|---|
| `0.1.0-alpha` | ✅ latest |
| anything older | ❌ |

## What "a vulnerability" means here

ProxiMight routes connections to proxies you choose. Its whole value is that a
connection either goes where you asked or does not go at all. So the bugs that
matter most are the ones where it **claims a protection it is not providing**:

- Traffic escaping a `Block` or `Proxy` rule and going out direct.
- The kill switch reporting armed/blocking while nothing is enforced.
- Anything that reveals your real IP when a rule said otherwise.
- Proxy credentials reaching a log, an error string, or the disk in cleartext.
- A hostile `.ovpn`/`.conf` influencing where traffic goes (config injection).
- Memory-safety bugs in code that parses untrusted input (VPN configs, proxy
  responses, profile files).

A crash is a bug. A **silent** leak is a vulnerability.

## Reporting

Use **GitHub's private vulnerability reporting** (Security → Report a
vulnerability) on this repository. Please do not open a public issue for a leak
path until it is fixed.

> If that tab is not there, private reporting has not been switched on yet
> (Settings → Security → Private vulnerability reporting) — say so in an issue
> **without** the details and it will be enabled. Do not post a leak path
> publicly just because the private channel is missing.

Useful report contents, roughly in order of value:

1. A concrete trigger — the config, rule, or sequence that reproduces it.
2. What you observed versus what the UI/logs claimed.
3. Build (`Debug`/`Release`), Windows version, and whether the WinDivert backend
   was active and elevated.

There is no bounty and no SLA. This is a personal project; expect best-effort.

## Known and documented weaknesses

These are already public and do **not** need reporting — see
[`docs/PRIVACY-SECURITY.md`](docs/PRIVACY-SECURITY.md) for the full list with
rationale:

- Traffic redirection is unverified on the wire (`caps.real == false`).
- Lockdown uses a stub firewall; it logs intended blocks rather than enforcing.
- Host-**name** rules cannot match on the WinDivert backend (numeric addresses
  only). The app warns about this.
- OpenVPN's management socket is started without a password.
- macOS support is scaffolding.

## Handling of secrets

- The profile is **sealed at rest** (DPAPI on Windows). Platforms without a
  provider write plaintext and log a loud warning.
- VPN key material is **never** copied into ProxiMight's data model — only the
  fact that a key is present, plus the path to the original file. A test
  byte-scans the parsed struct to prove it.
- Credentials are never written to the log. If you find a path where they are,
  that is a vulnerability worth reporting.

## Third-party components

ProxiMight does **not** bundle WinDivert (LGPLv3/GPLv3, kernel driver) or any
VPN client. You supply and verify those yourself — deliberately, so the trust
chain stays yours. See [`docs/SETUP-WINDIVERT.md`](docs/SETUP-WINDIVERT.md).

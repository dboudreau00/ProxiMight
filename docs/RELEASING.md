# Releasing ProxiMight

How to cut a release, and the two decisions that are **not** mechanical.

---

## Decision 1: source only, or binaries too?

**Recommendation: source only.** It is the safe default and it matches the
project's own hard rule about never bundling the driver.

The reasoning is licensing, and it is worth understanding rather than copying:

- **ProxiMight itself is MIT.** Publishing the source is unambiguous.
- **WinDivert is dual LGPLv3 / GPLv3**, and it is a **kernel driver**. A
  ProxiMight binary built with the SDK links `WinDivert.lib` and needs
  `WinDivert.dll` + `WinDivert64.sys` beside it to do anything real.
- Shipping that bundle is **redistribution of WinDivert**, which brings
  obligations (license text, notices, and — under LGPL — the ability for a
  recipient to relink against their own copy). It also hands users a signed
  kernel driver whose provenance they did not check, which is exactly what
  `docs/SETUP-WINDIVERT.md` argues against.
- A binary built **without** the SDK is legally clean but functionally the stub
  backend: it cannot see or block real traffic. Shipping that as "ProxiMight"
  invites people to conclude the tool does nothing.

So: publish the source, and let people build with their own verified copy of the
driver. If you later want binaries, do the LGPL work deliberately — ship
`WinDivert`'s license and notices, keep the linkage dynamic, and say plainly in
the release notes which driver version the build expects.

## Decision 2: does the tag claim more than you have verified?

Before tagging, check the claims:

- Is `caps.real` still `false`? Then the release notes must say redirection is
  **unproven on the wire**, and the version keeps its `-alpha` suffix.
- Did anything in `docs/PRIVACY-SECURITY.md` get fixed since the last tag? The
  "Known limitations" section of `CHANGELOG.md` must match reality, not
  intentions.
- Keep a ledger of what is **verified by observation** versus merely
  implemented, and do not put anything from the second list into the release
  notes. `docs/PRIVACY-SECURITY.md` is the public version of that ledger.

The version string in `include/proximight/pmx.h` carries the suffix too — drop
`-alpha` only when the wire test in `docs/SETUP-WINDIVERT.md` has passed.

---

## Pre-flight checklist

```bash
# 1. Both presets build and test clean
tools/build.ps1                       ; tools/test.ps1
tools/build.ps1 -Preset windows-release ; tools/test.ps1 -Preset windows-release

# 2. Nothing untracked or uncommitted
git status --short

# 3. No secrets, no absolute user paths, in TRACKED files
git grep -nI -E "C:\\\\Users\\\\[A-Za-z]+|/Users/[a-z]+" -- . ':!build'
git grep -nI -E "api[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE" -- . ':!tests'

# 4. No binaries at all in the tree - in particular the driver, which must stay
#    user-supplied. (Matching the NAME "windivert" is useless here: our own
#    backend_windivert.c and the setup doc match it. Match binary EXTENSIONS.)
git ls-files | Select-String -Pattern "\.(exe|dll|sys|lib|obj|pdb)$"
#    -> should print nothing
```

Then confirm by eye:

- `CHANGELOG.md` has an entry for this version with an honest **Known
  limitations** section.
- `README.md`'s status section still matches what the code does.
- `SECURITY.md` points at a reporting channel that exists.

---

## Cutting the tag

```bash
git tag -a v0.1.0-alpha -m "ProxiMight v0.1.0-alpha — pre-alpha, source only"
git tag -n99 v0.1.0-alpha        # read it back before pushing
```

## Publishing (needs YOUR GitHub credentials)

Nothing above touched the network. These steps do, and they need you to be
authenticated — do not hand your token to anyone, including an assistant.

```bash
# One-time: create the repo. Keep it PRIVATE first if you want to review how it
# renders before the world sees it; you can flip it public later.
gh repo create ProxiMight --private --source=. --remote=origin

# Push history and the tag
git push -u origin main
git push origin phase1-windivert
git push origin v0.1.0-alpha

# Create the release from the changelog section
gh release create v0.1.0-alpha --title "ProxiMight v0.1.0-alpha" \
  --notes-file docs/release-notes-v0.1.0-alpha.md --prerelease
```

`--prerelease` is not optional while `caps.real` is `false`.

If `gh` is not installed: `winget install GitHub.cli`, then `gh auth login`
(browser flow — you authenticate, nobody else).

---

## After publishing

- Turn on **private vulnerability reporting** (Settings → Security) so
  `SECURITY.md`'s instructions are true.
- Add topics: `windows`, `proxy`, `socks5`, `privacy`, `windivert`, `c`.
- If the repo is public, re-read `README.md`'s first screen as a stranger. The
  honest-status paragraph is the most important thing on the page.

# winget (Windows Package Manager) listing

Lets IT departments install and update with one command:

    winget install CybX.NetworkLens
    winget upgrade CybX.NetworkLens

winget takes manifests from the public repository
https://github.com/microsoft/winget-pkgs, so publishing is a pull request there
(one per version). The manifests must point at a **published** release asset
and carry its SHA-256, so generate them after the GitHub release is public:

    python packaging/winget/make_manifests.py 1.3.0

This writes `manifests/c/CybX/NetworkLens/1.3.0/*.yaml` (the winget-pkgs
layout) with the installer URL and checksum taken from the release's
`SHA256SUMS`. Then either:

- run `wingetcreate submit manifests/c/CybX/NetworkLens/1.3.0` (install the
  `wingetcreate` tool once: `winget install Microsoft.WingetCreate`) from a
  Windows machine signed in to GitHub, or
- copy the folder into a fork of winget-pkgs and open the PR by hand.

The first submission goes through a manual review; later versions are
automated. Unsigned installers are accepted (the checksum is what winget
verifies), but a signed installer gets through review with fewer questions.

# Changelog

All notable changes to kiwi-plugin-vpn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); kiwi-updater installs the
latest tag matching `^v?[0-9]+(\.[0-9]+){0,3}$`.

## [Unreleased]

## [0.2.1] - 2026-10-29

### Changed
- Wording: kiwi-proxy works per exit, not per kiwi-fox profile, and the module's
  texts now say so.

## [0.2.0] - 2026-10-29

### Changed
- Now a **kiwi-proxy** provider module: kiwi-fox's proxy engine moved to
  [kiwi-proxy](https://github.com/derlocke-ng/kiwi-proxy), which loads this module
  for every consumer (kiwi-fox, kiwi-pentesting, exits published on the host). The
  module imports `kiwi_proxy.models` / `kiwi_proxy.providers.base` (was
  `kiwi_fox.core.…`), installs into `~/.local/share/kiwi-proxy/modules/`, labels its
  containers `kiwi-proxy.*`, builds `kiwi-proxy/…` images, and depends on kiwi-proxy.
- `install.sh` removes the copy under kiwi-fox's old modules directory and takes its
  module state along.

## [0.1.0] - 2026-10-28

### Added
- Initial VPN provider module for kiwi-fox, built on gluetun: a `TunnelProvider`
  that runs gluetun on the `kf-providers` bridge and a microsocks adapter in its
  network namespace, exposing SOCKS5 that rides the tunnel.
- gluetun is configured from `modules-state/vpn/vpn.json` (and an optional
  read-only `gluetun/` directory), so credentials stay off the command line and out
  of `podman inspect`. Leases map to gluetun's `SERVER_COUNTRIES`.
- `module/provider.py` (`VpnProvider`, `MANIFEST`), the adapter image
  (`module/containers/adapter/`), `kiwi.manifest`, `install.sh`, and unit tests
  against the kiwi-fox provider contract.

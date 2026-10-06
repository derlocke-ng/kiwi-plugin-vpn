# Changelog

All notable changes to kiwi-plugin-vpn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); kiwi-updater installs the
latest tag matching `^v?[0-9]+(\.[0-9]+){0,3}$`.

## [Unreleased]

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

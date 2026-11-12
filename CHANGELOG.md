# Changelog

All notable changes to kiwi-plugin-vpn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); kiwi-updater installs the
latest tag matching `^v?[0-9]+(\.[0-9]+){0,3}$`.

## [Unreleased]

## [0.7.0] - 2026-11-13

### Added
- **A WireGuard MTU too big for the path is fitted.** Before the tunnel starts,
  the module pings the server with packets that may not be split; when the
  config's MTU plus WireGuard's 60 bytes (80 over IPv6) is more than the path
  takes, the tunnel uses the largest that fits and says so on the exit (Kiwi
  Proxy 0.17 shows it: "MTU 1316, fitted to the path (config 1352)", the why
  behind a (?)). The stored config is unchanged; a config without an MTU stays
  gluetun's (it finds the path's own); a server that does not answer pings keeps
  the config's. Measured on the dev VM, whose way out takes 1376-byte packets:
  MTU 1352 there failed every download (TLS reset, handshakes fine), 1280 and
  the fitted 1316 none. A path that fits costs two pings (0.2 s).

## [0.6.1] - 2026-11-11

### Fixed
- **A refused login says so at once** ("the VPN refused the login (AUTH_FAILED)")
  instead of a two-minute timeout: 3 s on the VM.
- **An OpenVPN server that does not answer is left for another.** gluetun
  connects to a config's first server only; when it does not answer, the exit
  starts again with another first, up to three. A config with one server says
  "the VPN server did not answer" (22 s on the VM instead of a timeout).
- gluetun's own VPN restarts stay off, with why (measured on the VM).

## [0.6.0] - 2026-11-11

### Added
- **OpenVPN configs that ask for a username and password** (most providers'):
  the login goes inline (`<auth-user-pass>`, OpenVPN 2.6), so the exit's secret
  is one whole config. `--login USER` in kiwi-proxy 0.16, rows in the app, and a
  NetworkManager connection brings its saved login along. Checked on the VM
  against a test OpenVPN server: the right login connects and passes traffic, a
  wrong one fails with AUTH_FAILED.

## [0.5.1] - 2026-11-11

### Fixed
- The same WireGuard key is refused only towards the same server. 0.4.0 refused
  any second exit with the key, which blocked a provider's per-server configs
  (they share one key) from running side by side.

## [0.5.0] - 2026-11-11

### Added
- **Import from NetworkManager.** Its WireGuard and OpenVPN connections are
  offered (`kiwi-proxy module sources vpn`, Import… in Kiwi Proxy). WireGuard is
  built from the connection's settings and secrets over D-Bus (NetworkManager
  hands the key over in your desktop session, and says so when it does not);
  OpenVPN is exported, its certificate files inlined, NetworkManager's quotes,
  user, group and scripts left out. Needs kiwi-proxy 0.15.0.

### Fixed
- An OpenVPN config whose client certificate has expired is refused when it is
  added, with the day it expired, instead of a tunnel that times out after two
  minutes (seen on the VM: a Riseup connection from early November).

## [0.4.0] - 2026-11-11

### Added
- A host SOCKS5 port on a VPN exit: published on the exit's gluetun (the
  namespace the gateway shares) and let in by gluetun's firewall. Needs
  kiwi-proxy 0.13.0.
- The exit is labelled by the server its config connects to.

## [0.3.1] - 2026-11-11

### Fixed
- 0.3.0's release was not published: `pyproject.toml` still said 0.2.2, and the
  release check requires every version to agree. The module is 0.3.0's.

## [0.3.0] - 2026-11-11

### Changed
- **One config per exit, TCP and UDP through the tunnel.** `kiwi-proxy add NAME
  --module vpn --config FILE` takes your WireGuard `.conf` or OpenVPN `.ovpn`
  (keys inside). It is checked (a full tunnel, for the internet) and kept as the
  exit's secret. The exit's gluetun owns the namespace and the gateway joins it
  (kiwi-proxy 0.11's tunnel exits), so a Kiwi Custodia box gets UDP too and
  nothing leaves with the tunnel down. Checked on the dev VM with WireGuard and
  OpenVPN-over-TCP configs, two exits at once.
- gluetun's own DNS, public-IP and version lookups are off (kiwi resolves and
  measures); its health check dials addresses and does not restart the tunnel.
  A WireGuard endpoint given by name is resolved first, the config's MTU is
  passed on, and OpenVPN servers on port 53 go last (gluetun uses the first).
- An exit does not start while another VPN exit is up with the same WireGuard
  key: a key works in one place at a time, and two tunnels with it take turns at
  the server and break each other (seen on the dev VM).

### Removed
- The module-wide `vpn.json`, the `gluetun/` folder and the microsocks adapter
  (its image, its smoke test and the images workflow). CI runs the unit tests.

### Fixed
- gluetun could not start: with every capability dropped it could not chown its
  files ("operation not permitted"). It gets the six it needs, without NET_RAW.

## [0.2.2] - 2026-11-07

### Fixed
- The adapter image did not build: `apk add microsocks` found no package, because
  microsocks is in no stable Alpine repository, only in edge/testing. It is now
  built from its v1.0.5 release tag, checked against the commit, in a builder
  stage; the final image is Alpine plus the one binary. Nothing in CI builds the
  module's images, so this is the first time it was built.

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

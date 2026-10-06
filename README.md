# kiwi-plugin-vpn

A [kiwi-fox](https://github.com/derlocke-ng/kiwi-fox) provider module: exit a
browser identity through a **WireGuard/OpenVPN tunnel**, using
[gluetun](https://github.com/qdm12/gluetun).

gluetun supports a long list of VPN providers but does not itself speak SOCKS5, so
this module runs gluetun on the `kf-providers` bridge and a tiny **microsocks
adapter in gluetun's network namespace** — SOCKS5 that rides the tunnel and is
reachable on the bridge at gluetun's address. (This is kiwi-fox's `TunnelProvider`
pattern; the same shape as kiwi-plugin-myst.)

A VPN subscription is required.

## Install

```sh
kiwi install kiwi-plugin-vpn
kiwi-fox module setup vpn     # pulls gluetun, builds kiwi-fox/vpn-adapter:latest
```

## Configure (once)

gluetun is configured with its own environment variables and files, kept in the
module's state directory so they are not per profile and never appear in
`podman inspect`:

```
~/.local/share/kiwi-fox/modules-state/vpn/
    vpn.json        provider settings as JSON, e.g.
                    {
                      "VPN_SERVICE_PROVIDER": "mullvad",
                      "VPN_TYPE": "wireguard",
                      "WIREGUARD_ADDRESSES": "10.x.x.x/32",
                      "leases": ["Sweden", "Netherlands"]
                    }
    gluetun/        optional, mounted read-only at /gluetun
                    (e.g. a wireguard.conf for the "custom" provider)
```

Every `UPPER_CASE` key in `vpn.json` is passed straight to gluetun — see the
[gluetun wiki](https://github.com/qdm12/gluetun-wiki) for the full set (provider
names, `SERVER_COUNTRIES`, WireGuard keys, OpenVPN credentials, …). The optional
`leases` list is what `kiwi-fox module leases vpn` shows and selects with
`--lease`; a lease (or `--country`) is passed to gluetun as `SERVER_COUNTRIES`
verbatim, so use gluetun's own naming.

Keep real keys out of git — the module state directory is outside this repo.

## Use

```sh
kiwi-fox module leases vpn
kiwi-fox new work --module vpn --lease Sweden
kiwi-fox run work
```

## How it fits

```
gluetun container ──────── kf-providers bridge ── kiwi-fox gateway ── browser
  tunnel up, /dev/net/tun                          permits only <gluetun-ip>:1080
     ▲ shares netns
microsocks adapter  (SOCKS5 0.0.0.0:1080, rides the tunnel)
```

The adapter is removed before gluetun on teardown (it joins gluetun's netns). A
shared tunnel serves every profile on the same lease and is torn down once no
running gateway still uses it.

## Status

The wiring, lifecycle, and gluetun/adapter containers are complete and unit-tested
against the kiwi-fox contract. Bringing a tunnel up end-to-end needs a real VPN
subscription and podman, so validate `module up vpn` on your own machine after
configuring `vpn.json`.

## Development

```sh
make setup && make test     # needs a kiwi-fox checkout beside this repo (or KIWI_FOX_SRC)
make lint
```

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).

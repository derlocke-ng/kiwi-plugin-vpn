# kiwi-plugin-vpn

A [kiwi-proxy](https://github.com/derlocke-ng/kiwi-proxy) provider module: an exit
through **your own WireGuard or OpenVPN config**, using
[gluetun](https://github.com/qdm12/gluetun). Everything on the exit — a Kiwi
Custodia box, a Kiwi Fox browser — goes through the VPN, **TCP and UDP**, and
nothing leaves any other way.

## Install

```sh
kiwi install kiwi-plugin-vpn
kiwi-proxy module setup vpn     # pulls gluetun
```

## Use

One config per exit, as your VPN gives it to you: a WireGuard `.conf` or an
OpenVPN `.ovpn` with its keys inside.

```sh
kiwi-proxy add home --module vpn --config ~/wg-home.conf
kiwi-proxy up home
kiwi-custodia new dev --exit home          # a box: TCP and UDP through the VPN
kiwi-fox new work --exit home              # a browser on it
```

In Kiwi Proxy: **New exit → Source: vpn → Config: Choose…**. Add as many VPN exits
as you like; each runs its own tunnel.

- **For the internet (WAN).** A WireGuard config must route `0.0.0.0/0`; one that
  only reaches a few subnets is refused.
- **The config is kept as the exit's secret** (the keyring, or kiwi-proxy's
  secret files), never in `podman inspect`. Deleting the exit deletes it.
- **One WireGuard key, one place.** Two tunnels with the same key take turns at
  the server and break each other, so an exit does not start while another is up
  with its key. A key also in use on another computer breaks the same way: give
  each exit a config (a peer) of its own.
- **DNS and ad-blocking are kiwi-proxy's**, per exit, like every exit's.
- An OpenVPN config that asks for a username and password, and a host SOCKS5
  port on a VPN exit, are not supported yet.

## How it fits

```
gluetun (one per exit) ── owns the network namespace; its firewall is the kill
   │                       switch, its route is the tunnel (WireGuard or OpenVPN)
   └─ kiwi-proxy gateway   joins it: kiwi's DNS and blocklists, a SOCKS5 for browsers
        ├─ Custodia box     joins the gateway: TCP and UDP straight through the tunnel
        └─ Kiwi Fox browser joins the gateway: through its SOCKS5
```

gluetun gets the config through its custom provider: a WireGuard endpoint given
by name is resolved first, OpenVPN servers on port 53 go last (gluetun connects
to the first `remote`), and the config's `MTU` is passed on. gluetun's own DNS,
public-IP and version lookups are off; kiwi-proxy measures the exit itself. If
the tunnel's container ends, the exit is taken down (fail closed) and the next
start brings a new one.

## Development

```sh
make setup && make test     # needs a kiwi-proxy checkout beside this repo (or KIWI_PROXY_SRC)
make lint
```

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).

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

Or one NetworkManager already has: `kiwi-proxy module sources vpn` lists them,
`kiwi-proxy add home --module vpn --from "My VPN"` takes one.

In Kiwi Proxy: **New exit → Source: vpn → Config: Choose…** (a file) or
**Import…** (NetworkManager). Add as many VPN exits
as you like; each runs its own tunnel.

- **For the internet (WAN).** A WireGuard config must route `0.0.0.0/0`; one that
  only reaches a few subnets is refused.
- **The config is kept as the exit's secret** (the keyring, or kiwi-proxy's
  secret files), never in `podman inspect`. Deleting the exit deletes it.
- **One WireGuard key, one server at a time.** Two tunnels with the same key to
  the same server take turns there and break each other, so an exit does not
  start while another is up that way. The same key on other servers is fine (a
  provider's per-server configs), but a key also in use on another computer, to
  the same server, breaks the same way.
- **DNS and ad-blocking are kiwi-proxy's**, per exit, like every exit's.
- **An OpenVPN config that asks for a username and password** (most providers'):
  `--login USER` (asked for the password) or the rows in the app. The login is
  kept inline in the exit's secret config; from NetworkManager it comes along.

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

**The MTU, fitted to the path.** A WireGuard config's `MTU` is right for the
network it was made on. Before the tunnel starts, the module pings the server
with packets that may not be split (two pings when the config fits, a few more
when it does not). When the config's MTU plus WireGuard's 60 bytes (80 over IPv6)
is more than the path takes, the tunnel gets the largest MTU that fits, and Kiwi
Proxy shows it on the exit ("MTU 1316, fitted to the path (config 1352)"); the
stored config stays as it is. A config without an `MTU` line leaves it to
gluetun, which finds the path's own. A server that does not answer pings keeps
the config's MTU. Seen on the dev VM, whose way out is a VPN gateway taking
1376-byte packets: MTU 1352 there failed every download, the fitted 1316 none.

## Development

```sh
make setup && make test     # needs a kiwi-proxy checkout beside this repo (or KIWI_PROXY_SRC)
make lint
```

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).

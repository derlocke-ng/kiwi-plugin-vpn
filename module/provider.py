"""VPN provider: exit through your own WireGuard or OpenVPN config, using gluetun.

A VPN exit is a tunnel exit (``joins="tunnel"``): the exit's own gluetun owns the
network namespace, gluetun's firewall is the kill switch and its route is the
tunnel. The exit's gateway joins it, so whatever runs on the exit — a Kiwi
Custodia box, a browser — gets TCP and UDP through the VPN, and nothing leaves
any other way.

Each exit has its own config, a WireGuard ``.conf`` or an OpenVPN ``.ovpn``,
checked here when the exit is added (``kiwi-proxy add NAME --module vpn --config
FILE``) and kept as the exit's secret. On start it is prepared for gluetun's
custom provider (a WireGuard endpoint given by name is resolved; OpenVPN servers
on port 53 go last, since gluetun connects to the first ``remote``) and handed
over as a podman secret. gluetun's own lookups are off — its DNS server, its
public-IP check, its version check: the exit's DNS and blocklists are kiwi's,
and kiwi measures the exit itself.

A VPN exit is for the internet (WAN): a WireGuard config must route 0.0.0.0/0.
"""

from __future__ import annotations

import ipaddress
import random
import re
import socket

from kiwi_proxy import podman, secrets
from kiwi_proxy.models import ContainerSpec, ProviderManifest
from kiwi_proxy.providers.base import ProviderError, TunnelProvider

GLUETUN_IMAGE = "docker.io/qmcgaw/gluetun:latest"
CONFIG_KIND = "vpnconfig"
WIREGUARD_TARGET = "/gluetun/wireguard/wg0.conf"
OPENVPN_TARGET = "/gluetun/custom.conf"
READY_MARKS = ("Initialization Sequence Completed", "wireguard setup is complete")

MANIFEST = ProviderManifest(
    name="vpn",
    title="VPN",
    description="exit through your WireGuard or OpenVPN config",
    version="0.4.0",
    image=GLUETUN_IMAGE,
    auth="none",
    needs_account=True,
    requires=[],
    joins="tunnel",
    notes="one config per exit: kiwi-proxy add NAME --module vpn --config FILE",
)

# gluetun's own lookups, off: kiwi resolves (per exit, with its blocklists) and
# measures. Its health check dials addresses, not names, and a failed check does
# not restart the tunnel under the exit's members.
QUIET = {
    "DNS_SERVER": "off",
    "DNS_UPSTREAM_RESOLVER_TYPE": "plain",
    "DNS_UPSTREAM_PLAIN_ADDRESSES": "1.1.1.1:53",
    "BLOCK_MALICIOUS": "off",
    "BLOCK_ADS": "off",
    "PUBLICIP_ENABLED": "off",
    "VERSION_INFORMATION": "off",
    "HEALTH_RESTART_VPN": "off",
    "HEALTH_TARGET_ADDRESSES": "1.1.1.1:443,9.9.9.9:443",
}


# ------------------------------------------------------------------ the config
def kind_of(text: str) -> str:
    if re.search(r"(?mi)^\s*\[Interface\]", text):
        return "wireguard"
    if re.search(r"(?m)^\s*remote\s+\S+", text) and re.search(
        r"(?m)^\s*(client|tls-client)\b", text
    ):
        return "openvpn"
    raise ProviderError("not a WireGuard (.conf) or OpenVPN (.ovpn) client config")


def _wg_values(text: str, key: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(rf"(?mi)^\s*{key}\s*=\s*(.+?)\s*$", text):
        out += [v.strip() for v in m.group(1).split(",") if v.strip()]
    return out


def _full_tunnel(allowed: list[str]) -> bool:
    for net in allowed:
        try:
            n = ipaddress.ip_network(net, strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen == 0:
            return True
    return False


def check_config(text: str) -> str:
    """What a config is, in a few words, or a ProviderError saying why it cannot be
    a VPN exit. Nothing is resolved or started."""
    kind = kind_of(text)
    if kind == "wireguard":
        for key in ("PrivateKey", "PublicKey", "Endpoint"):
            if not _wg_values(text, key):
                raise ProviderError(f"the WireGuard config has no {key}")
        allowed = _wg_values(text, "AllowedIPs")
        if not _full_tunnel(allowed):
            reach = ", ".join(allowed) or "nothing"
            raise ProviderError(
                f"this config only reaches {reach}; a VPN exit needs a full tunnel "
                "(AllowedIPs = 0.0.0.0/0)"
            )
        return f"WireGuard · {_wg_values(text, 'Endpoint')[0]}"
    if re.search(r"(?m)^\s*auth-user-pass\b", text) and "<auth-user-pass>" not in text:
        raise ProviderError(
            "the OpenVPN config asks for a username and password; "
            "only configs with their keys inside are supported for now"
        )
    remotes = re.findall(r"(?m)^\s*remote\s+\S+", text)
    proto = re.search(r"(?m)^\s*proto\s+(\w+)", text)
    p = proto.group(1).upper().split("-")[0] if proto else "UDP"
    return f"OpenVPN · {len(remotes)} server{'s' if len(remotes) != 1 else ''}, {p}"


def server_of(text: str) -> tuple[str, int] | None:
    """The VPN server a config connects to, for the exit's label: WireGuard's
    Endpoint, or OpenVPN's first remote."""
    if kind_of(text) == "wireguard":
        m = re.match(r"\[?([^\]]+?)\]?:(\d+)$", _wg_values(text, "Endpoint")[0])
        return (m.group(1), int(m.group(2))) if m else None
    m = re.search(r"(?m)^\s*remote\s+(\S+)(?:\s+(\d+))?", text)
    return (m.group(1), int(m.group(2) or 1194)) if m else None


def _resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError as exc:
        raise ProviderError(f"cannot resolve the VPN server {host!r}: {exc}") from exc


def prepare(text: str, *, rng: random.Random | None = None) -> tuple[str, str, dict[str, str]]:
    """(kind, the config as gluetun gets it, extra gluetun settings)."""
    kind = kind_of(text)
    extra: dict[str, str] = {}
    if kind == "wireguard":

        def endpoint(m: re.Match[str]) -> str:
            return f"{m.group(1)}{_resolve(m.group(2))}:{m.group(3)}"

        text = re.sub(r"(?mi)^(\s*Endpoint\s*=\s*)([^:\s\[\]]+):(\d+)", endpoint, text)
        if mtu := _wg_values(text, "MTU"):
            extra["WIREGUARD_MTU"] = re.sub(r"\D", "", mtu[0])
        return kind, text, extra
    lines = text.splitlines(keepends=True)
    is_remote = [bool(re.match(r"\s*remote\s+\S+", ln)) for ln in lines]
    remotes = [ln for ln, r in zip(lines, is_remote, strict=True) if r]

    def port_of(ln: str) -> str:
        parts = ln.split()
        return parts[2] if len(parts) > 2 else "1194"

    first = [ln for ln in remotes if port_of(ln) != "53"]
    (rng or random.Random()).shuffle(first)
    ordered = first + [ln for ln in remotes if port_of(ln) == "53"]
    at = is_remote.index(True)
    out = [ln for ln, r in zip(lines[:at], is_remote[:at], strict=True) if not r]
    out += ordered
    out += [ln for ln, r in zip(lines[at:], is_remote[at:], strict=True) if not r]
    return kind, "".join(out), extra


def _host_port(lease: str, env: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    """An exit's host SOCKS5 port: published on this tunnel (the namespace the
    gateway shares), let in by gluetun's firewall, and labelled so kiwi-proxy
    starts the tunnel again when the port changes."""
    from kiwi_proxy import exits, gateway, paths

    try:
        ex = exits.load(lease)
    except exits.ExitError:
        return [], {}
    if not ex.expose:
        return [], {}
    env["FIREWALL_INPUT_PORTS"] = str(gateway.EXPOSE_PORT)
    return [gateway.expose_publish(ex)], {paths.EXPOSE_LABEL: ex.expose.address}


def secret_name(lease: str) -> str:
    return f"kf-vpn-{lease[:12]}"


def wireguard_key(text: str) -> str | None:
    keys = _wg_values(text, "PrivateKey") if kind_of(text) == "wireguard" else []
    return keys[0] if keys else None


def _key_in_use(lease: str, key: str) -> str | None:
    """The name of another VPN exit that is up with this WireGuard key. A key
    works in one place at a time: two tunnels with it take turns at the server
    and break each other."""
    from kiwi_proxy import exits, paths

    for c in podman.ps(all_=False, labels={paths.MODULE_LABEL: "vpn", paths.ROLE_LABEL: "tunnel"}):
        other = (c.get("Labels") or {}).get(paths.LEASE_LABEL)
        if not other or other == lease:
            continue
        text = secrets.lookup(other, kind=CONFIG_KIND)
        try:
            if text and wireguard_key(text) == key:
                return exits.load(other).name
        except (ProviderError, exits.ExitError):
            continue
    return None


# -------------------------------------------------------------------- provider
class VpnProvider(TunnelProvider):
    manifest = MANIFEST
    # A handshake, and for OpenVPN a TLS exchange, can take a while.
    ready_timeout = 120.0
    log_marker = "[vpn]"

    def check_config(self, text: str) -> str:
        return check_config(text)

    def config_server(self, text: str) -> tuple[str, int] | None:
        return server_of(text)

    def tunnel_spec(self, ctx, *, lease=None, country=None):
        text = secrets.lookup(lease, kind=CONFIG_KIND) if lease else None
        if not text:
            raise ProviderError(
                "this VPN exit has no config; add one: "
                "kiwi-proxy add NAME --module vpn --config FILE"
            )
        if (key := wireguard_key(text)) and (other := _key_in_use(lease, key)):
            raise ProviderError(
                f"exit {other!r} is up with the same WireGuard key; a key works in "
                "one place at a time (take it down, or give this exit its own config)"
            )
        kind, prepared, extra = prepare(text)
        name = secret_name(lease)
        podman.secret_set(name, prepared)
        target = WIREGUARD_TARGET if kind == "wireguard" else OPENVPN_TARGET
        env = {"VPN_SERVICE_PROVIDER": "custom", "VPN_TYPE": kind, **QUIET, **extra}
        if kind == "openvpn":
            env["OPENVPN_CUSTOM_CONFIG"] = OPENVPN_TARGET
        publish, labels = _host_port(lease, env)
        return ContainerSpec(
            name=ctx.container_name(lease),
            image=ctx.image,
            network=ctx.network,
            env=env,
            secrets=[(name, target)],
            devices=["/dev/net/tun"],
            # NET_ADMIN for the tunnel and its firewall; gluetun also chowns and
            # writes its own files and switches users. Measured on the dev VM with
            # WireGuard and OpenVPN. No NET_RAW: on the providers bridge it would
            # let a compromised tunnel ARP-spoof its neighbours.
            cap_drop=["all"],
            cap_add=["NET_ADMIN", "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"],
            security_opt=["no-new-privileges"],
            userns=None,
            tmpfs=["/tmp"],
            publish=publish,
            labels={"kiwi-proxy.module": self.name, "kiwi-proxy.role": "tunnel", **labels},
        )

    def tunnel_ready(self, ctx, container):
        logs = podman.logs(container, tail=200)
        return any(mark in logs for mark in READY_MARKS)

    def down(self, ctx, *, lease=None):
        super().down(ctx, lease=lease)
        if lease:
            podman.secret_rm(secret_name(lease))

    def leases(self, ctx):
        return []  # one config per exit, not a list to choose from


PROVIDER = VpnProvider()

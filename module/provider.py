"""VPN provider: exit through a WireGuard/OpenVPN tunnel, using gluetun.

gluetun brings the tunnel up but does not offer SOCKS5, so this is a TunnelProvider:
gluetun runs on the providers bridge, and a tiny microsocks adapter runs in gluetun's
network namespace, exposing SOCKS5 that rides the tunnel and is reachable on the
bridge at gluetun's address. Adapting the tunnel into plain SOCKS5 is the module's job.

A VPN subscription is required. Its settings — the service provider, the protocol,
the keys/credentials, server selection — are gluetun's own environment variables and
files, given once and kept in the module's state directory, not per profile:

    ~/.local/share/kiwi-fox/modules-state/vpn/
        vpn.json          {"VPN_SERVICE_PROVIDER": "mullvad", "VPN_TYPE": "wireguard", ...}
        gluetun/          mounted read-only at /gluetun (e.g. a wireguard.conf)

See the README. gluetun documents every variable:
https://github.com/qdm12/gluetun-wiki
"""

from __future__ import annotations

import json

from kiwi_fox.core.models import ContainerSpec, Lease, ProviderManifest
from kiwi_fox.core.providers.base import TunnelProvider

GLUETUN_IMAGE = "docker.io/qmcgaw/gluetun:latest"
SOCKS_PORT = 1080
CONFIG_FILE = "vpn.json"

MANIFEST = ProviderManifest(
    name="vpn",
    title="VPN (gluetun)",
    description="exit through a WireGuard/OpenVPN tunnel",
    version="0.1.0",
    image=GLUETUN_IMAGE,
    socks_port=SOCKS_PORT,
    auth="none",
    needs_account=True,
    requires=[],
    notes="needs a VPN subscription; configure under modules-state/vpn/ (see README)",
)


class VpnProvider(TunnelProvider):
    manifest = MANIFEST
    # A tunnel handshake plus the public-IP check gluetun does can take a while.
    ready_timeout = 120.0

    def _config(self, ctx) -> dict:
        path = ctx.state_dir / CONFIG_FILE
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            return {}

    def tunnel_spec(self, ctx, *, lease=None, country=None):
        cfg = self._config(ctx)
        env = {
            "VPN_SERVICE_PROVIDER": str(cfg.get("VPN_SERVICE_PROVIDER", "custom")),
            "VPN_TYPE": str(cfg.get("VPN_TYPE", "wireguard")),
        }
        # Any other UPPER_CASE key in the config is passed straight to gluetun.
        for key, value in cfg.items():
            if key.isupper():
                env[key] = str(value)
        # A lease/country selects the server; gluetun expects its own naming
        # (e.g. a full country name), so it is passed through verbatim.
        target = lease or country
        if target:
            env.setdefault("SERVER_COUNTRIES", str(target))

        gluetun_dir = ctx.state_dir / "gluetun"
        volumes = []
        if gluetun_dir.exists():
            # Read-only, and a bind mount rather than env, so keys never show up in
            # `podman inspect`.
            volumes.append((str(gluetun_dir), "/gluetun", "ro,z"))

        return ContainerSpec(
            name=ctx.container_name(lease),
            image=ctx.image,
            network=ctx.network,
            env=env,
            volumes=volumes,
            devices=["/dev/net/tun"],
            cap_drop=["all"],
            cap_add=["NET_ADMIN"],  # bring the tunnel interface up and route through it
            security_opt=["no-new-privileges"],
            # Container-root, so gluetun can configure the tun device — and so the
            # adapter (keep-id) joining this netns matches the proven kiwi-fox
            # gateway(None)+browser(keep-id) namespace pairing.
            userns=None,
            tmpfs=["/tmp", "/run"],
            labels={"kiwi-fox.module": self.name, "kiwi-fox.role": "tunnel"},
        )

    def tunnel_ready(self, ctx, container):
        from kiwi_fox.core import podman

        logs = podman.logs(container, tail=200).lower()
        # gluetun prints one of these once the tunnel is established.
        return "healthy" in logs or "public ip address is" in logs

    def leases(self, ctx):
        cfg = self._config(ctx)
        return [Lease(id=str(c), label=str(c)) for c in cfg.get("leases", [])]


PROVIDER = VpnProvider()

"""The vpn (gluetun) provider against the real kiwi-fox contract."""

from __future__ import annotations

import json

from kiwi_fox.core import podman
from kiwi_fox.core.providers.base import Provider, TunnelProvider


def test_manifest(manifest):
    assert manifest.name == "vpn"
    assert manifest.socks_port == 1080
    assert manifest.auth == "none"
    assert manifest.needs_account is True
    assert manifest.image.endswith("gluetun:latest")


def test_provider_is_a_tunnel_provider(provider):
    assert isinstance(provider, Provider)
    assert isinstance(provider, TunnelProvider)


def test_tunnel_spec_is_on_the_bridge_with_a_tun_device(provider, ctx):
    spec = provider.tunnel_spec(ctx, lease="Sweden")
    assert spec.network == "kf-providers"
    assert spec.image == ctx.image
    assert "/dev/net/tun" in spec.devices
    assert spec.cap_add == ["NET_ADMIN"]
    assert spec.env["SERVER_COUNTRIES"] == "Sweden"


def test_adapter_rides_the_tunnel_netns(provider, ctx):
    tunnel = ctx.container_name("se")
    adapter = provider.adapter_spec(ctx, tunnel, lease="se")
    assert adapter.network == f"container:{tunnel}"
    assert adapter.image == "kiwi-fox/vpn-adapter:latest"
    assert adapter.args == ["1080"]
    args = podman.spec_args(adapter)
    assert "--privileged" not in args


def test_config_drives_gluetun_env(provider, ctx):
    (ctx.state_dir / "vpn.json").write_text(
        json.dumps(
            {"VPN_SERVICE_PROVIDER": "mullvad", "VPN_TYPE": "wireguard", "leases": ["se", "nl"]}
        )
    )
    spec = provider.tunnel_spec(ctx)
    assert spec.env["VPN_SERVICE_PROVIDER"] == "mullvad"
    assert spec.env["VPN_TYPE"] == "wireguard"
    assert {lease.id for lease in provider.leases(ctx)} == {"se", "nl"}


def test_gluetun_dir_is_mounted_read_only_when_present(provider, ctx):
    (ctx.state_dir / "gluetun").mkdir()
    spec = provider.tunnel_spec(ctx)
    assert any(dst == "/gluetun" and "ro" in opts for _src, dst, opts in spec.volumes)

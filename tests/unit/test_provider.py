"""The VPN module: one WireGuard/OpenVPN config per exit, gluetun as a tunnel
the exit's gateway joins (TCP and UDP through the VPN)."""

from __future__ import annotations

import random
import subprocess

import pytest
from kiwi_proxy import podman, secrets
from kiwi_proxy.providers.base import ProviderError, TunnelProvider

WG = """[Interface]
PrivateKey = aGVsbG8gd29ybGQ=
Address = 10.8.0.2/24
DNS = 10.8.0.1
MTU = 1352

[Peer]
PublicKey = d29ybGQgaGVsbG8=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.org:51820
PersistentKeepalive = 25
"""
WG_SPLIT = WG.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.8.0.1/24")
OVPN = """client
dev tun
proto tcp
remote 203.0.113.1 53
remote 203.0.113.2 1194
remote 203.0.113.3 80
remote-random
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
x
-----END CERTIFICATE-----
</ca>
"""


def test_manifest_is_a_tunnel_the_gateway_joins(manifest, provider):
    assert manifest.name == "vpn" and manifest.joins == "tunnel"
    assert isinstance(provider, TunnelProvider)


def test_a_full_wireguard_tunnel_is_accepted(module):
    assert module.check_config(WG) == "WireGuard · vpn.example.org:51820"


def test_a_config_that_only_reaches_subnets_is_refused(module):
    with pytest.raises(ProviderError, match=r"only reaches 10\.8\.0\.1/24.*full tunnel"):
        module.check_config(WG_SPLIT)


def test_an_openvpn_config_with_its_keys_inside_is_accepted(module):
    assert module.check_config(OVPN) == "OpenVPN · 3 servers, TCP"


def test_an_openvpn_config_asking_for_a_login_is_refused_for_now(module):
    with pytest.raises(ProviderError, match="username and password"):
        module.check_config(OVPN + "auth-user-pass\n")


def test_something_else_is_refused(module):
    with pytest.raises(ProviderError, match="not a WireGuard"):
        module.check_config("hello\n")


def test_wireguard_gets_its_endpoint_resolved_and_its_mtu(module, monkeypatch):
    monkeypatch.setattr(module.socket, "gethostbyname", lambda h: "198.51.100.4")
    kind, text, extra = module.prepare(WG)
    assert kind == "wireguard"
    assert "Endpoint = 198.51.100.4:51820" in text and "vpn.example.org" not in text
    assert extra == {"WIREGUARD_MTU": "1352"}


def test_openvpn_servers_on_port_53_go_last(module):
    _kind, text, extra = module.prepare(OVPN, rng=random.Random(1))
    remotes = [ln.split()[2] for ln in text.splitlines() if ln.startswith("remote ")]
    assert remotes[-1] == "53" and sorted(remotes[:2]) == ["1194", "80"]
    assert text.splitlines()[:3] == ["client", "dev tun", "proto tcp"]  # the rest stays
    assert "<ca>" in text and extra == {}


@pytest.fixture
def stored(monkeypatch):
    kept: dict[str, str] = {}
    monkeypatch.setattr(secrets, "lookup", lambda item, kind="endpoint": kept.get(f"{item}/{kind}"))
    monkeypatch.setattr(podman, "secret_set", lambda name, value: kept.__setitem__(name, value))
    monkeypatch.setattr(podman, "secret_rm", lambda name: kept.pop(name, None))
    return kept


def test_the_tunnel_gets_its_config_as_a_secret_and_stays_quiet(provider, module, ctx, stored):
    stored["exit-1/vpnconfig"] = OVPN
    spec = provider.tunnel_spec(ctx, lease="exit-1")
    assert spec.name == ctx.container_name("exit-1") and spec.network == "kf-providers"
    assert spec.secrets == [("kf-vpn-exit-1", "/gluetun/custom.conf")]
    assert stored["kf-vpn-exit-1"].count("remote ") == 3  # the prepared config
    env = spec.env
    assert env["VPN_SERVICE_PROVIDER"] == "custom" and env["VPN_TYPE"] == "openvpn"
    assert env["OPENVPN_CUSTOM_CONFIG"] == "/gluetun/custom.conf"
    for off in ("DNS_SERVER", "PUBLICIP_ENABLED", "VERSION_INFORMATION", "HEALTH_RESTART_VPN"):
        assert env[off] == "off"
    assert spec.devices == ["/dev/net/tun"] and "NET_ADMIN" in spec.cap_add
    assert spec.cap_drop == ["all"] and "NET_RAW" not in spec.cap_add
    assert {"CHOWN", "SETUID", "SETGID"} <= set(spec.cap_add)  # gluetun chowns, switches users
    assert spec.userns is None  # container-root, for the tun device


def test_wireguard_goes_where_gluetun_reads_it(provider, module, ctx, stored, monkeypatch):
    monkeypatch.setattr(module.socket, "gethostbyname", lambda h: "198.51.100.4")
    stored["exit-2/vpnconfig"] = WG
    spec = provider.tunnel_spec(ctx, lease="exit-2")
    assert spec.secrets == [("kf-vpn-exit-2", "/gluetun/wireguard/wg0.conf")]
    assert spec.env["VPN_TYPE"] == "wireguard" and spec.env["WIREGUARD_MTU"] == "1352"


def test_an_exit_without_a_config_says_how_to_give_one(provider, ctx, stored):
    with pytest.raises(ProviderError, match="--config FILE"):
        provider.tunnel_spec(ctx, lease="exit-3")


def test_ready_when_openvpn_or_wireguard_says_so(provider, ctx, monkeypatch):
    for line, ready in (
        ("[openvpn] Initialization Sequence Completed", True),
        ("[vpn] wireguard setup is complete. Note wireguard is a silent protocol", True),
        ("[openvpn] TLS Error: client->client", False),
    ):
        monkeypatch.setattr(podman, "logs", lambda name, tail=200, line=line: line)
        assert provider.tunnel_ready(ctx, "c") is ready


def test_down_takes_the_config_secret_away(provider, ctx, stored, monkeypatch):
    monkeypatch.setattr(podman, "rm", lambda name, **k: None)
    stored["kf-vpn-exit-1"] = "x"
    provider.down(ctx, lease="exit-1")
    assert "kf-vpn-exit-1" not in stored


def test_a_wireguard_key_up_on_another_exit_is_refused(provider, module, ctx, stored, monkeypatch):
    from kiwi_proxy import exits, paths
    from kiwi_proxy.models import Endpoint

    other = exits.create("home", Endpoint(host="10.89.231.9", port=1080, module="vpn"))
    stored[f"{other.id}/vpnconfig"] = WG
    stored["exit-4/vpnconfig"] = WG  # the same key
    monkeypatch.setattr(
        podman,
        "ps",
        lambda all_=True, labels=None: [{"Labels": {paths.LEASE_LABEL: other.id}}],
    )
    with pytest.raises(ProviderError, match="'home' is up with the same WireGuard key"):
        provider.tunnel_spec(ctx, lease="exit-4")
    stored["exit-4/vpnconfig"] = WG.replace("aGVsbG8gd29ybGQ=", "b3RoZXIga2V5")  # its own key
    monkeypatch.setattr(module.socket, "gethostbyname", lambda h: "198.51.100.4")
    assert provider.tunnel_spec(ctx, lease="exit-4").env["VPN_TYPE"] == "wireguard"


def test_an_exit_is_labelled_by_its_vpn_server(module):
    assert module.server_of(WG) == ("vpn.example.org", 51820)
    assert module.server_of(OVPN) == ("203.0.113.1", 53)


def test_a_host_socks5_port_is_published_on_the_tunnel(provider, ctx, stored):
    from kiwi_proxy import exits
    from kiwi_proxy.models import Endpoint, Expose

    ex = exits.create("home", Endpoint(host="203.0.113.1", port=1194, module="vpn"))
    ex.expose = Expose(port=1091)
    exits.save(ex)
    stored[f"{ex.id}/vpnconfig"] = OVPN
    spec = provider.tunnel_spec(ctx, lease=ex.id)
    assert spec.publish == ["127.0.0.1:1091:1081/tcp"]
    assert spec.env["FIREWALL_INPUT_PORTS"] == "1081"
    assert spec.labels["kiwi-proxy.expose"] == "127.0.0.1:1091"
    other = exits.create("plain", Endpoint(host="203.0.113.2", port=1194, module="vpn"))
    stored[f"{other.id}/vpnconfig"] = OVPN
    plain = provider.tunnel_spec(ctx, lease=other.id)
    assert plain.publish == [] and "FIREWALL_INPUT_PORTS" not in plain.env


# ------------------------------------------------------ NetworkManager import
def _v(t, d):
    return {"type": t, "data": d}


NM_SETTINGS = {
    "wireguard": {
        "mtu": _v("u", 1412),
        "peers": _v(
            "aa{sv}",
            [
                {
                    "public-key": _v("s", "UGVlcktleQ=="),
                    "endpoint": _v("s", "94.16.108.143:51820"),
                    "allowed-ips": _v("as", ["0.0.0.0/0", "::/0"]),
                    "persistent-keepalive": _v("u", 25),
                }
            ],
        ),
    },
    "ipv4": {
        "address-data": _v("aa{sv}", [{"address": _v("s", "10.8.0.5"), "prefix": _v("u", 24)}])
    },
    "ipv6": {"address-data": _v("aa{sv}", [])},
}
NM_SECRETS = {
    "wireguard": {
        "private-key": _v("s", "UHJpdmF0ZUtleQ=="),
        "peers": _v(
            "aa{sv}", [{"public-key": _v("s", "UGVlcktleQ=="), "preshared-key": _v("s", "UFNL")}]
        ),
    }
}


def test_the_connection_list_keeps_names_with_colons(module):
    text = "u-1:wireguard:home\\: vpn\nu-2:vpn:riseup\nu-3:802-3-ethernet:wired\n"
    assert module.parse_nm_list(text) == [
        ("u-1", "wireguard", "home: vpn"),
        ("u-2", "vpn", "riseup"),
        ("u-3", "802-3-ethernet", "wired"),
    ]


def test_a_wireguard_connection_becomes_a_wg_quick_config(module):
    text = module.wireguard_from_nm(NM_SETTINGS, NM_SECRETS)
    assert module.check_config(text) == "WireGuard · 94.16.108.143:51820"
    for line in (
        "PrivateKey = UHJpdmF0ZUtleQ==",
        "Address = 10.8.0.5/24",
        "MTU = 1412",
        "PublicKey = UGVlcktleQ==",
        "PresharedKey = UFNL",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "Endpoint = 94.16.108.143:51820",
        "PersistentKeepalive = 25",
    ):
        assert line in text.splitlines(), line


def test_without_the_key_it_says_so(module):
    with pytest.raises(ProviderError, match="did not hand over the WireGuard key"):
        module.wireguard_from_nm(NM_SETTINGS, {"wireguard": {}})


def test_an_exported_openvpn_config_is_made_whole(module, tmp_path):
    (tmp_path / "ca.pem").write_text("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")
    (tmp_path / "ta.key").write_text("TA\n")
    exported = (
        "client\nremote '203.0.113.1' 1194\nproto 'tcp-client'\nuser nm-openvpn\ngroup nm-openvpn\n"
        f"ca '{tmp_path}/ca.pem'\ntls-auth {tmp_path}/ta.key 1\nscript-security 2\n"
    )
    text = module.openvpn_inline(exported)
    assert "user " not in text and "group " not in text and "script-security" not in text
    assert "<ca>\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n</ca>" in text
    assert "key-direction 1\n<tls-auth>\nTA\n</tls-auth>" in text
    assert "remote 203.0.113.1 1194" in text  # NetworkManager's quotes gone
    assert module.check_config(text) == "OpenVPN · 1 server, TCP"
    assert module.server_of(text) == ("203.0.113.1", 1194)


def test_the_module_offers_what_networkmanager_has(provider, module, ctx, monkeypatch):
    calls = []

    def run(args, timeout=20):
        calls.append(args)
        if args[:2] == ["nmcli", "-t"]:
            out = (
                "u-1:wireguard:home\nu-2:vpn:riseup\nu-3:vpn:work-pptp\nu-4:802-3-ethernet:wired\n"
            )
        elif args[:3] == ["nmcli", "-g", "vpn.service-type"]:
            out = (
                module.OPENVPN_SERVICE
                if args[-1] == "u-2"
                else "org.freedesktop.NetworkManager.pptp"
            )
        else:
            out = ""
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    monkeypatch.setattr(module, "_run", run)
    found = provider.config_sources(ctx)
    assert [(s.id, s.label, s.detail) for s in found] == [
        ("u-1", "home", "WireGuard"),
        ("u-2", "riseup", "OpenVPN"),
    ]


def test_an_expired_client_certificate_is_named(module, tmp_path):
    import datetime as dt
    import shutil

    if not shutil.which("openssl"):
        pytest.skip("no openssl")
    key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=kiwi-test",
        ],
        check=True,
        capture_output=True,
    )
    conf = OVPN + f"<cert>\n{cert.read_text()}</cert>\n"
    assert module.cert_expired(conf) is None  # valid today
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=400)
    tomorrow = (dt.datetime.now(dt.UTC) + dt.timedelta(days=1)).date().isoformat()
    assert module.cert_expired(conf, now=later) == tomorrow  # -days 1: ends a day from now
    assert module.check_config(conf) == "OpenVPN · 3 servers, TCP"

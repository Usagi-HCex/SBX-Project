#!/usr/bin/env python3
"""Generate sing-box/Xray configs and local share links from manager state.

This module deliberately performs no network I/O and never sends state data to a
third party.  It is kept separate from the interactive shell so generation can
be unit-tested without root privileges or a running proxy core.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import pathlib
import re
import sys
import urllib.parse
from typing import Any


SUPPORTED_PROTOCOLS = {
    "sb-vless-reality",
    "sb-vless-ws",
    "sb-vmess-ws",
    "sb-hysteria2",
    "sb-tuic",
    "sb-anytls",
    "sb-shadowsocks",
    "xr-vless-reality",
    "xr-vless-ws",
    "xr-vmess-ws",
    "xr-vless-xhttp-reality",
    "xr-trojan",
    "xr-shadowsocks",
}

ARGO_PROTOCOLS = {
    "sb-vless-ws",
    "sb-vmess-ws",
    "xr-vless-ws",
    "xr-vmess-ws",
}

TLS_PROTOCOLS = {
    "sb-hysteria2",
    "sb-tuic",
    "sb-anytls",
    "xr-trojan",
}

DISPLAY_NAMES = {
    "sb-vless-reality": "Sing-box VLESS Reality Vision",
    "sb-vless-ws": "Sing-box VLESS WebSocket",
    "sb-vmess-ws": "Sing-box VMess WebSocket",
    "sb-hysteria2": "Sing-box Hysteria2",
    "sb-tuic": "Sing-box TUIC v5",
    "sb-anytls": "Sing-box AnyTLS",
    "sb-shadowsocks": "Sing-box Shadowsocks 2022",
    "xr-vless-reality": "Xray VLESS Reality Vision",
    "xr-vless-ws": "Xray VLESS WebSocket",
    "xr-vmess-ws": "Xray VMess WebSocket",
    "xr-vless-xhttp-reality": "Xray VLESS XHTTP Reality",
    "xr-trojan": "Xray Trojan TLS",
    "xr-shadowsocks": "Xray Shadowsocks 2022",
}

TCP_PROTOCOLS = {
    "sb-vless-reality",
    "sb-vless-ws",
    "sb-vmess-ws",
    "sb-anytls",
    "xr-vless-reality",
    "xr-vless-ws",
    "xr-vmess-ws",
    "xr-vless-xhttp-reality",
    "xr-trojan",
}

UDP_PROTOCOLS = {
    "sb-hysteria2",
    "sb-tuic",
}

DUAL_PROTOCOLS = {
    "sb-shadowsocks",
    "xr-shadowsocks",
}

SHADOWSOCKS_2022_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}

TUIC_CONGESTION_CONTROLS = {"cubic", "new_reno", "bbr"}
VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none"}
REALITY_FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "randomized"}
HYSTERIA2_BBR_PROFILES = {"conservative", "standard", "aggressive"}


class StateError(ValueError):
    pass


def normalize_ip_identifiers(value: str) -> list[str]:
    parts = [part for part in re.split(r"[\s,;]+", value.strip()) if part]
    if not 1 <= len(parts) <= 2:
        raise StateError("enter one IP, or one IPv4 and one IPv6")
    try:
        addresses = [ipaddress.ip_address(part) for part in parts]
    except ValueError as exc:
        raise StateError(f"invalid IP address: {exc}") from exc
    if len({address.version for address in addresses}) != len(addresses):
        raise StateError("only one address per IP family is allowed")
    if any(not address.is_global for address in addresses):
        raise StateError("IP certificate identifiers must be public global addresses")
    return [str(address) for address in addresses]


def load_state(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        state = json.load(handle)
    validate_state(state)
    return state


def validate_state(state: dict[str, Any]) -> None:
    if state.get("schema") != 1:
        raise StateError("unsupported state schema")
    protocols = state.get("protocols")
    if not isinstance(protocols, dict):
        raise StateError("protocols must be an object")
    used_ports: dict[int, str] = {}
    for protocol_id, item in protocols.items():
        if protocol_id not in SUPPORTED_PROTOCOLS:
            raise StateError(f"unsupported protocol: {protocol_id}")
        if not isinstance(item, dict):
            raise StateError(f"invalid protocol record: {protocol_id}")
        port = item.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise StateError(f"invalid port for {protocol_id}")
        if port in used_ports:
            raise StateError(
                f"port {port} is shared by {used_ports[port]} and {protocol_id}"
            )
        used_ports[port] = protocol_id
        required = required_fields(protocol_id)
        missing = [field for field in required if not item.get(field)]
        if missing:
            raise StateError(f"{protocol_id} missing: {', '.join(missing)}")
        if "path" in item and not re.fullmatch(r"/[A-Za-z0-9._~/-]{1,200}", str(item["path"])):
            raise StateError(f"invalid path for {protocol_id}")
        if protocol_id.endswith("-ws") and not isinstance(item.get("tls", False), bool):
            raise StateError(f"invalid WebSocket TLS flag for {protocol_id}")
        if protocol_id in {"sb-vmess-ws", "xr-vmess-ws"} and item.get("cipher", "auto") not in VMESS_CIPHERS:
            raise StateError(f"invalid VMess cipher for {protocol_id}")
        if "reality" in protocol_id:
            handshake_port = item.get("handshake_port", 443)
            if not isinstance(handshake_port, int) or not 1 <= handshake_port <= 65535:
                raise StateError(f"invalid Reality handshake port for {protocol_id}")
            if item.get("fingerprint", "chrome") not in REALITY_FINGERPRINTS:
                raise StateError(f"invalid Reality fingerprint for {protocol_id}")
        has_vless_encryption = "decryption" in item or "encryption" in item
        if has_vless_encryption:
            if protocol_id not in {"xr-vless-reality", "xr-vless-ws", "xr-vless-xhttp-reality"}:
                raise StateError(f"VLESS Encryption is only supported by Xray profiles: {protocol_id}")
            if not isinstance(item.get("decryption"), str) or not item["decryption"]:
                raise StateError(f"missing VLESS decryption for {protocol_id}")
            if not isinstance(item.get("encryption"), str) or not item["encryption"]:
                raise StateError(f"missing VLESS encryption for {protocol_id}")
            if item.get("vless_encryption_auth", "x25519") not in {"x25519", "mlkem768"}:
                raise StateError(f"invalid VLESS Encryption authentication for {protocol_id}")
        if protocol_id == "sb-tuic" and item.get("congestion_control", "bbr") not in TUIC_CONGESTION_CONTROLS:
            raise StateError("invalid TUIC congestion control")
        if protocol_id in DUAL_PROTOCOLS and item.get("method") not in SHADOWSOCKS_2022_METHODS:
            raise StateError(f"invalid Shadowsocks 2022 method for {protocol_id}")
        if protocol_id == "sb-hysteria2":
            if not isinstance(item.get("ignore_client_bandwidth", False), bool):
                raise StateError("invalid Hysteria2 ignore_client_bandwidth flag")
            for field in ("up_mbps", "down_mbps"):
                value = item.get(field)
                if value is not None and (not isinstance(value, int) or not 1 <= value <= 100000):
                    raise StateError(f"invalid Hysteria2 {field}")
            if ("up_mbps" in item) != ("down_mbps" in item):
                raise StateError("Hysteria2 bandwidth limits must be configured as a pair")
            if item.get("ignore_client_bandwidth") and "up_mbps" in item:
                raise StateError("Hysteria2 bandwidth limits conflict with forced BBR mode")
            if item.get("bbr_profile", "standard") not in HYSTERIA2_BBR_PROFILES:
                raise StateError("invalid Hysteria2 BBR profile")
            obfs = item.get("obfs")
            if obfs is not None:
                if not isinstance(obfs, dict) or obfs.get("type") != "salamander" or not obfs.get("password"):
                    raise StateError("invalid Hysteria2 obfs configuration")
            hopping = item.get("port_hopping")
            if hopping is not None:
                if not isinstance(hopping, dict) or hopping.get("enabled") is not True:
                    raise StateError("invalid Hysteria2 port hopping configuration")
                start = hopping.get("start")
                end = hopping.get("end")
                if not isinstance(start, int) or not isinstance(end, int) or not (1 <= start < end <= 65535):
                    raise StateError("invalid Hysteria2 port hopping range")
                for other_id, other_item in protocols.items():
                    if other_id == protocol_id or other_id not in UDP_PROTOCOLS | DUAL_PROTOCOLS:
                        continue
                    if isinstance(other_item, dict) and start <= other_item.get("port", 0) <= end:
                        raise StateError(
                            f"Hysteria2 port hopping range conflicts with {other_id}"
                        )
    route = state.get("routing", {})
    if route.get("mode") not in {"direct", "warp"}:
        raise StateError("routing.mode must be direct or warp")
    socks_port = route.get("socks_port")
    if not isinstance(socks_port, int) or not 1 <= socks_port <= 65535:
        raise StateError("invalid routing.socks_port")
    argo = state.get("argo", {})
    if argo.get("mode", "off") not in {"off", "quick", "fixed"}:
        raise StateError("invalid argo mode")
    target = argo.get("target", "")
    if target and (target not in protocols or target not in ARGO_PROTOCOLS):
        raise StateError("Argo target is not an installed WebSocket protocol")
    certificate = state.get("certificate", {})
    if any(
        protocol_id in TLS_PROTOCOLS or item.get("tls") is True
        for protocol_id, item in protocols.items()
    ) and not certificate.get("domain"):
        raise StateError("a certificate identity is required by a TLS inbound")
    if certificate.get("kind") == "ip":
        identifiers = certificate.get("identifiers")
        if not isinstance(identifiers, list):
            raise StateError("IP certificate identifiers must be an array")
        normalized = normalize_ip_identifiers(" ".join(map(str, identifiers)))
        if certificate.get("domain") not in normalized:
            raise StateError("certificate.domain must be one of the IP identifiers")


def required_fields(protocol_id: str) -> set[str]:
    common = {"port"}
    if protocol_id in {"sb-vless-reality", "xr-vless-reality"}:
        return common | {
            "uuid",
            "server_name",
            "private_key",
            "public_key",
            "short_id",
        }
    if protocol_id == "xr-vless-xhttp-reality":
        return common | {
            "uuid",
            "server_name",
            "private_key",
            "public_key",
            "short_id",
            "path",
        }
    if protocol_id in {"sb-vless-ws", "xr-vless-ws"}:
        return common | {"uuid", "path"}
    if protocol_id in {"sb-vmess-ws", "xr-vmess-ws"}:
        return common | {"uuid", "path"}
    if protocol_id == "sb-tuic":
        return common | {"uuid", "password"}
    if protocol_id in {"sb-hysteria2", "sb-anytls", "xr-trojan"}:
        return common | {"password"}
    if protocol_id in {"sb-shadowsocks", "xr-shadowsocks"}:
        return common | {"password", "method"}
    return common


def tls_paths(state: dict[str, Any]) -> tuple[str, str]:
    cert = state.get("certificate", {})
    fullchain = cert.get("fullchain", "/etc/sbx-manager/certs/fullchain.pem")
    key = cert.get("key", "/etc/sbx-manager/certs/private.key")
    return str(fullchain), str(key)


def singbox_inbound(protocol_id: str, item: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tag": protocol_id,
        "listen": "::",
        "listen_port": item["port"],
    }
    cert_path, key_path = tls_paths(state)
    if protocol_id == "sb-vless-reality":
        base.update(
            {
                "type": "vless",
                "users": [{"name": "sbx", "uuid": item["uuid"], "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True,
                    "server_name": item["server_name"],
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": item["server_name"],
                            "server_port": item.get("handshake_port", 443),
                        },
                        "private_key": item["private_key"],
                        "short_id": [item["short_id"]],
                    },
                },
            }
        )
    elif protocol_id in {"sb-vless-ws", "sb-vmess-ws"}:
        base.update(
            {
                "type": "vless" if "vless" in protocol_id else "vmess",
                "users": [{"name": "sbx", "uuid": item["uuid"]}],
                "transport": {"type": "ws", "path": item["path"]},
            }
        )
        if item.get("tls"):
            base["tls"] = {
                "enabled": True,
                "certificate_path": cert_path,
                "key_path": key_path,
            }
    elif protocol_id == "sb-hysteria2":
        base.update(
            {
                "type": "hysteria2",
                "users": [{"name": "sbx", "password": item["password"]}],
                "tls": {"enabled": True, "certificate_path": cert_path, "key_path": key_path},
                "masquerade": {
                    "type": "string",
                    "status_code": 404,
                    "headers": {"content-type": "text/plain; charset=utf-8"},
                    "content": "Not Found",
                },
                "ignore_client_bandwidth": item.get("ignore_client_bandwidth", False),
                "disable_path_mtu_discovery": False,
            }
        )
        if item.get("obfs"):
            base["obfs"] = item["obfs"]
        if "up_mbps" in item:
            base["up_mbps"] = item["up_mbps"]
            base["down_mbps"] = item["down_mbps"]
        base["bbr_profile"] = item.get("bbr_profile", "standard")
    elif protocol_id == "sb-tuic":
        base.update(
            {
                "type": "tuic",
                "users": [
                    {"name": "sbx", "uuid": item["uuid"], "password": item["password"]}
                ],
                "congestion_control": item.get("congestion_control", "bbr"),
                "auth_timeout": "3s",
                "zero_rtt_handshake": False,
                "heartbeat": "10s",
                "disable_path_mtu_discovery": False,
                "tls": {
                    "enabled": True,
                    "alpn": ["h3"],
                    "certificate_path": cert_path,
                    "key_path": key_path,
                },
            }
        )
    elif protocol_id == "sb-anytls":
        base.update(
            {
                "type": "anytls",
                "users": [{"name": "sbx", "password": item["password"]}],
                "padding_scheme": [
                    "stop=8",
                    "0=30-30",
                    "1=100-400",
                    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
                    "3=9-9,500-1000",
                    "4=500-1000",
                    "5=500-1000",
                    "6=500-1000",
                    "7=500-1000",
                ],
                "tls": {"enabled": True, "certificate_path": cert_path, "key_path": key_path},
            }
        )
    elif protocol_id == "sb-shadowsocks":
        base.update(
            {
                "type": "shadowsocks",
                "method": item["method"],
                "password": item["password"],
            }
        )
    else:
        raise StateError(f"not a sing-box protocol: {protocol_id}")
    return base


def build_singbox(state: dict[str, Any]) -> dict[str, Any]:
    inbounds = [
        singbox_inbound(protocol_id, item, state)
        for protocol_id, item in sorted(state["protocols"].items())
        if protocol_id.startswith("sb-")
    ]
    socks_port = state["routing"]["socks_port"]
    outbounds = [
        {"type": "direct", "tag": "direct"},
        {
            "type": "socks",
            "tag": "warp",
            "server": "127.0.0.1",
            "server_port": socks_port,
            "version": "5",
        },
    ]
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "final": "warp" if state["routing"]["mode"] == "warp" else "direct",
            "auto_detect_interface": True,
        },
    }


def xray_inbound(protocol_id: str, item: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tag": protocol_id,
        "listen": "::",
        "port": item["port"],
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }
    cert_path, key_path = tls_paths(state)
    if protocol_id in {"xr-vless-reality", "xr-vless-xhttp-reality"}:
        is_xhttp = protocol_id.endswith("xhttp-reality")
        stream: dict[str, Any] = {
            "network": "xhttp" if is_xhttp else "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "target": f"{item['server_name']}:{item.get('handshake_port', 443)}",
                "serverNames": [item["server_name"]],
                "privateKey": item["private_key"],
                "shortIds": [item["short_id"]],
            },
        }
        if is_xhttp:
            stream["xhttpSettings"] = {"path": item["path"], "mode": "auto"}
        base.update(
            {
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": item["uuid"], "flow": "xtls-rprx-vision"}],
                    "decryption": item.get("decryption", "none"),
                },
                "streamSettings": stream,
            }
        )
    elif protocol_id in {"xr-vless-ws", "xr-vmess-ws"}:
        is_vless = "vless" in protocol_id
        client: dict[str, Any] = {"id": item["uuid"]}
        if is_vless and item.get("decryption"):
            client["flow"] = "xtls-rprx-vision"
        if not is_vless:
            client["alterId"] = 0
        base.update(
            {
                "protocol": "vless" if is_vless else "vmess",
                "settings": {
                    "clients": [client],
                    **({"decryption": item.get("decryption", "none")} if is_vless else {}),
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls" if item.get("tls") else "none",
                    "wsSettings": {"path": item["path"]},
                },
            }
        )
        if item.get("tls"):
            base["streamSettings"]["tlsSettings"] = {
                "certificates": [
                    {"certificateFile": cert_path, "keyFile": key_path}
                ]
            }
    elif protocol_id == "xr-trojan":
        base.update(
            {
                "protocol": "trojan",
                "settings": {"clients": [{"password": item["password"]}]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            {"certificateFile": cert_path, "keyFile": key_path}
                        ]
                    },
                },
            }
        )
    elif protocol_id == "xr-shadowsocks":
        base.update(
            {
                "protocol": "shadowsocks",
                "settings": {
                    "method": item["method"],
                    "password": item["password"],
                    "network": "tcp,udp",
                },
            }
        )
    else:
        raise StateError(f"not an Xray protocol: {protocol_id}")
    return base


def build_xray(state: dict[str, Any]) -> dict[str, Any]:
    inbounds = [
        xray_inbound(protocol_id, item, state)
        for protocol_id, item in sorted(state["protocols"].items())
        if protocol_id.startswith("xr-")
    ]
    direct = {"tag": "direct", "protocol": "freedom", "settings": {}}
    warp = {
        "tag": "warp",
        "protocol": "socks",
        "settings": {
            "servers": [
                {
                    "address": "127.0.0.1",
                    "port": state["routing"]["socks_port"],
                }
            ]
        },
    }
    outbounds = [warp, direct] if state["routing"]["mode"] == "warp" else [direct, warp]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def host_for_uri(host: str) -> str:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if parsed.version == 6 else host


def fragment(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def query(params: dict[str, Any]) -> str:
    return urllib.parse.urlencode(params, doseq=True, safe="/")


def b64_text(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def vmess_link(
    item: dict[str, Any], host: str, name: str, tls_name: str = "", argo_host: str | None = None
) -> str:
    address = argo_host or host
    tls_enabled = bool(argo_host or item.get("tls"))
    payload = {
        "v": "2",
        "ps": name,
        "add": address,
        "port": "443" if argo_host else str(item["port"]),
        "id": item["uuid"],
        "aid": "0",
        "scy": item.get("cipher", "auto"),
        "net": "ws",
        "type": "none",
        "host": argo_host or (tls_name if tls_enabled else ""),
        "path": item["path"],
        "tls": "tls" if tls_enabled else "",
        "sni": argo_host or (tls_name if tls_enabled else ""),
        "alpn": "http/1.1" if tls_enabled else "",
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode()).decode()


def share_link(protocol_id: str, item: dict[str, Any], state: dict[str, Any]) -> str:
    server = str(state.get("server") or "SERVER_IP")
    prefix = str(state.get("node_prefix") or "SBX")
    name = f"{prefix}-{DISPLAY_NAMES[protocol_id]}"
    argo = state.get("argo", {})
    argo_host = None
    if argo.get("target") == protocol_id and argo.get("hostname"):
        argo_host = str(argo["hostname"])
    host = host_for_uri(argo_host or server)
    port = 443 if argo_host else item["port"]
    cert_domain = str(state.get("certificate", {}).get("domain", ""))

    if protocol_id in {"sb-vmess-ws", "xr-vmess-ws"}:
        return vmess_link(item, server, name, cert_domain, argo_host)
    if protocol_id in {"sb-vless-ws", "xr-vless-ws"}:
        tls_enabled = bool(argo_host or item.get("tls"))
        params = {
            "encryption": item.get("encryption", "none"),
            "security": "tls" if tls_enabled else "none",
            "type": "ws",
            "path": item["path"],
        }
        if item.get("encryption"):
            params["flow"] = "xtls-rprx-vision"
        if tls_enabled:
            tls_server_name = argo_host or cert_domain
            params.update({"host": tls_server_name, "sni": tls_server_name, "alpn": "http/1.1"})
        return f"vless://{item['uuid']}@{host}:{port}?{query(params)}#{fragment(name)}"
    if protocol_id in {"sb-vless-reality", "xr-vless-reality"}:
        params = {
            "encryption": item.get("encryption", "none"),
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": item["server_name"],
            "fp": item.get("fingerprint", "chrome"),
            "pbk": item["public_key"],
            "sid": item["short_id"],
            "type": "tcp",
        }
        return f"vless://{item['uuid']}@{host}:{port}?{query(params)}#{fragment(name)}"
    if protocol_id == "xr-vless-xhttp-reality":
        params = {
            "encryption": item.get("encryption", "none"),
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": item["server_name"],
            "fp": item.get("fingerprint", "chrome"),
            "pbk": item["public_key"],
            "sid": item["short_id"],
            "type": "xhttp",
            "path": item["path"],
            "mode": "auto",
        }
        return f"vless://{item['uuid']}@{host}:{port}?{query(params)}#{fragment(name)}"
    if protocol_id == "sb-hysteria2":
        params = {
            "security": "tls",
            "sni": cert_domain,
            "alpn": "h3",
            "insecure": "0",
        }
        if item.get("obfs"):
            params.update(
                {
                    "obfs": item["obfs"]["type"],
                    "obfs-password": item["obfs"]["password"],
                }
            )
        hopping = item.get("port_hopping", {})
        if hopping.get("enabled") and not argo_host:
            # v2rayN/v2rayNG parse the authority with a standard URI parser,
            # so the authority port must stay numeric.  Their established
            # compatibility extension carries the hopping range in mport.
            params["mport"] = f"{hopping['start']}-{hopping['end']}"
        return f"hysteria2://{fragment(item['password'])}@{host}:{port}/?{query(params)}#{fragment(name)}"
    if protocol_id == "sb-tuic":
        params = {
            "sni": cert_domain,
            "alpn": "h3",
            "congestion_control": item.get("congestion_control", "bbr"),
        }
        return f"tuic://{item['uuid']}:{fragment(item['password'])}@{host}:{port}?{query(params)}#{fragment(name)}"
    if protocol_id == "sb-anytls":
        params = {"security": "tls", "sni": cert_domain}
        return f"anytls://{fragment(item['password'])}@{host}:{port}?{query(params)}#{fragment(name)}"
    if protocol_id == "xr-trojan":
        params = {"security": "tls", "sni": cert_domain, "type": "tcp"}
        return f"trojan://{fragment(item['password'])}@{host}:{port}?{query(params)}#{fragment(name)}"
    if protocol_id in {"sb-shadowsocks", "xr-shadowsocks"}:
        userinfo = b64_text(f"{item['method']}:{item['password']}")
        return f"ss://{userinfo}@{host}:{port}#{fragment(name)}"
    raise StateError(f"cannot make share link for {protocol_id}")


def build_nodes(state: dict[str, Any]) -> str:
    lines: list[str] = []
    for protocol_id, item in sorted(state["protocols"].items()):
        lines.append(f"[{DISPLAY_NAMES[protocol_id]}]")
        lines.append(share_link(protocol_id, item, state))
        lines.append("")
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def firewall_plan(state: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return the host-firewall ports and NAT redirects owned by SBX."""
    validate_state(state)
    ports: list[dict[str, Any]] = []
    redirects: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()

    def add_port(protocol: str, start: int, end: int, source: str) -> None:
        key = (protocol, start, end)
        if key not in seen:
            ports.append(
                {"protocol": protocol, "start": start, "end": end, "source": source}
            )
            seen.add(key)

    for protocol_id, item in sorted(state["protocols"].items()):
        port = item["port"]
        if protocol_id in TCP_PROTOCOLS | DUAL_PROTOCOLS:
            add_port("tcp", port, port, protocol_id)
        if protocol_id in UDP_PROTOCOLS | DUAL_PROTOCOLS:
            add_port("udp", port, port, protocol_id)
        if protocol_id == "sb-hysteria2":
            hopping = item.get("port_hopping", {})
            if hopping.get("enabled"):
                start, end = hopping["start"], hopping["end"]
                add_port("udp", start, end, protocol_id)
                redirects.append(
                    {
                        "protocol": "udp",
                        "start": start,
                        "end": end,
                        "target": port,
                        "source": protocol_id,
                    }
                )
    ports.sort(key=lambda item: (item["protocol"], item["start"], item["end"]))
    return {"ports": ports, "redirects": redirects}


def write_json(path: str, value: Any) -> None:
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_text(path: str, value: str) -> None:
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)


def default_state() -> dict[str, Any]:
    return {
        "schema": 1,
        "node_prefix": "SBX",
        "server": "",
        "routing": {"mode": "direct", "socks_port": 40000},
        "certificate": {
            "domain": "",
            "acme_domain": "",
            "kind": "domain",
            "profile": "classic",
            "identifiers": [],
            "fullchain": "/etc/sbx-manager/certs/fullchain.pem",
            "key": "/etc/sbx-manager/certs/private.key",
        },
        "protocols": {},
        "argo": {
            "mode": "off",
            "target": "",
            "hostname": "",
            "tunnel_id": "",
            "account_id": "",
        },
        "watchdog": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--output", required=True)
    render = sub.add_parser("render")
    render.add_argument("--state", required=True)
    render.add_argument("--sing-box", required=True)
    render.add_argument("--xray", required=True)
    render.add_argument("--nodes", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--state", required=True)
    firewall = sub.add_parser("firewall-plan")
    firewall.add_argument("--state", required=True)
    normalize_ip = sub.add_parser("normalize-ip")
    normalize_ip.add_argument("--value", required=True)
    args = parser.parse_args()

    try:
        if args.command == "init":
            write_json(args.output, default_state())
        elif args.command == "validate":
            load_state(args.state)
        elif args.command == "normalize-ip":
            print(" ".join(normalize_ip_identifiers(args.value)))
        elif args.command == "firewall-plan":
            print(json.dumps(firewall_plan(load_state(args.state)), separators=(",", ":")))
        elif args.command == "render":
            state = load_state(args.state)
            write_json(args.sing_box, build_singbox(state))
            write_json(args.xray, build_xray(state))
            write_text(args.nodes, build_nodes(state))
    except (OSError, json.JSONDecodeError, StateError) as exc:
        print(f"sbx-generator: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

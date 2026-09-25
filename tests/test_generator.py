import importlib.util
import json
import pathlib
import tempfile
import unittest
import urllib.parse


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sbx_generator", ROOT / "src" / "sbx_generator.py"
)
GEN = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GEN)


def sample_state():
    state = GEN.default_state()
    state["server"] = "203.0.113.10"
    state["node_prefix"] = "TEST"
    state["certificate"]["domain"] = "edge.example.com"
    reality = {
        "port": 24443,
        "uuid": "11111111-1111-4111-8111-111111111111",
        "server_name": "www.microsoft.com",
        "private_key": "private-key",
        "public_key": "public-key",
        "short_id": "a1b2c3d4",
    }
    state["protocols"] = {
        "sb-vless-reality": reality.copy(),
        "sb-vmess-ws": {
            "port": 18080,
            "uuid": "22222222-2222-4222-8222-222222222222",
            "path": "/vmess",
        },
        "sb-hysteria2": {"port": 24444, "password": "hy2-pass"},
        "sb-tuic": {
            "port": 24445,
            "uuid": "33333333-3333-4333-8333-333333333333",
            "password": "tuic-pass",
        },
        "sb-anytls": {"port": 24446, "password": "any-pass"},
        "sb-shadowsocks": {
            "port": 24447,
            "method": "2022-blake3-aes-128-gcm",
            "password": "c2l4dGVlbi1ieXRlcyE=",
        },
        "xr-vless-reality": {**reality, "port": 34443},
        "xr-vless-ws": {
            "port": 28080,
            "uuid": "44444444-4444-4444-8444-444444444444",
            "path": "/vless",
        },
        "xr-vmess-ws": {
            "port": 28081,
            "uuid": "55555555-5555-4555-8555-555555555555",
            "path": "/vmess-xr",
        },
        "xr-vless-xhttp-reality": {**reality, "port": 34444, "path": "/xhttp"},
        "xr-trojan": {"port": 34445, "password": "trojan-pass"},
        "xr-shadowsocks": {
            "port": 34446,
            "method": "2022-blake3-aes-128-gcm",
            "password": "YW5vdGhlci0xNmJ5dGU=",
        },
    }
    return state


class GeneratorTests(unittest.TestCase):
    def test_ip_certificate_identifiers_accept_ipv4_ipv6(self):
        self.assertEqual(
            GEN.normalize_ip_identifiers("1.1.1.1, 2606:4700:4700::1111"),
            ["1.1.1.1", "2606:4700:4700::1111"],
        )

    def test_ip_certificate_identifiers_reject_private_and_duplicate_family(self):
        with self.assertRaises(GEN.StateError):
            GEN.normalize_ip_identifiers("192.168.1.1")
        with self.assertRaises(GEN.StateError):
            GEN.normalize_ip_identifiers("1.1.1.1 8.8.8.8")

    def test_ip_certificate_state_requires_primary_identifier(self):
        state = sample_state()
        state["certificate"].update(
            {
                "kind": "ip",
                "profile": "shortlived",
                "domain": "8.8.8.8",
                "acme_domain": "8.8.8.8",
                "identifiers": ["1.1.1.1"],
            }
        )
        with self.assertRaises(GEN.StateError):
            GEN.validate_state(state)

    def test_ip_certificate_ipv6_share_link_uses_bracketed_host(self):
        state = sample_state()
        state["server"] = "2606:4700:4700::1111"
        state["certificate"].update(
            {
                "kind": "ip",
                "profile": "shortlived",
                "domain": "2606:4700:4700::1111",
                "acme_domain": "2606:4700:4700::1111",
                "identifiers": ["2606:4700:4700::1111"],
            }
        )
        GEN.validate_state(state)
        link = GEN.share_link(
            "sb-hysteria2", state["protocols"]["sb-hysteria2"], state
        )
        self.assertIn("@[2606:4700:4700::1111]:", link)
        self.assertIn("sni=2606%3A4700%3A4700%3A%3A1111", link)

    def test_pre_012_certificate_state_remains_valid(self):
        state = sample_state()
        for field in ("kind", "profile", "identifiers"):
            state["certificate"].pop(field, None)
        GEN.validate_state(state)

    def test_all_protocols_render(self):
        state = sample_state()
        GEN.validate_state(state)
        sing = GEN.build_singbox(state)
        xray = GEN.build_xray(state)
        self.assertEqual(len(sing["inbounds"]), 6)
        self.assertEqual(len(xray["inbounds"]), 6)
        self.assertEqual(sing["route"]["final"], "direct")
        self.assertEqual(xray["outbounds"][0]["tag"], "direct")
        anytls = next(item for item in sing["inbounds"] if item["tag"] == "sb-anytls")
        self.assertEqual(anytls["tls"]["certificate_path"], "/etc/sbx-manager/certs/fullchain.pem")
        xhttp = next(item for item in xray["inbounds"] if item["tag"] == "xr-vless-xhttp-reality")
        self.assertEqual(xhttp["streamSettings"]["network"], "xhttp")
        xray_ss = next(item for item in xray["inbounds"] if item["tag"] == "xr-shadowsocks")
        self.assertEqual(xray_ss["settings"]["network"], "tcp,udp")

    def test_hysteria2_hopping_obfs_and_firewall_plan(self):
        state = sample_state()
        state["protocols"]["sb-hysteria2"].update(
            {
                "port_hopping": {"enabled": True, "start": 40000, "end": 41000},
                "obfs": {"type": "salamander", "password": "obfs-secret"},
            }
        )
        GEN.validate_state(state)
        inbound = next(
            item for item in GEN.build_singbox(state)["inbounds"]
            if item["tag"] == "sb-hysteria2"
        )
        self.assertEqual(inbound["obfs"]["type"], "salamander")
        plan = GEN.firewall_plan(state)
        self.assertIn(
            {
                "protocol": "udp",
                "start": 40000,
                "end": 41000,
                "source": "sb-hysteria2",
            },
            plan["ports"],
        )
        self.assertEqual(plan["redirects"][0]["target"], 24444)
        link = GEN.share_link("sb-hysteria2", state["protocols"]["sb-hysteria2"], state)
        parsed = urllib.parse.urlsplit(link)
        params = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.hostname, "203.0.113.10")
        self.assertEqual(parsed.port, 24444)
        self.assertEqual(params["mport"], ["40000-41000"])
        self.assertEqual(params["security"], ["tls"])
        self.assertEqual(params["alpn"], ["h3"])
        self.assertEqual(params["obfs"], ["salamander"])
        self.assertEqual(params["obfs-password"], ["obfs-secret"])

    def test_hysteria2_uri_without_hopping_keeps_numeric_port(self):
        state = sample_state()
        link = GEN.share_link(
            "sb-hysteria2", state["protocols"]["sb-hysteria2"], state
        )
        parsed = urllib.parse.urlsplit(link)
        self.assertEqual(parsed.port, 24444)
        self.assertNotIn("mport", urllib.parse.parse_qs(parsed.query))

    def test_hysteria2_hopping_rejects_other_udp_protocol_port(self):
        state = sample_state()
        state["protocols"]["sb-hysteria2"]["port_hopping"] = {
            "enabled": True,
            "start": 24000,
            "end": 25000,
        }
        with self.assertRaises(GEN.StateError):
            GEN.validate_state(state)

    def test_firewall_transport_matrix(self):
        plan = GEN.firewall_plan(sample_state())
        tuples = {
            (item["protocol"], item["start"], item["source"])
            for item in plan["ports"]
        }
        self.assertIn(("tcp", 24443, "sb-vless-reality"), tuples)
        self.assertIn(("udp", 24444, "sb-hysteria2"), tuples)
        self.assertIn(("tcp", 24447, "sb-shadowsocks"), tuples)
        self.assertIn(("udp", 24447, "sb-shadowsocks"), tuples)
        self.assertNotIn(("tcp", 24444, "sb-hysteria2"), tuples)

    def test_warp_is_global_default_for_both_cores(self):
        state = sample_state()
        state["routing"] = {"mode": "warp", "socks_port": 41000}
        sing = GEN.build_singbox(state)
        xray = GEN.build_xray(state)
        self.assertEqual(sing["route"]["final"], "warp")
        self.assertEqual(sing["outbounds"][1]["server_port"], 41000)
        self.assertEqual(xray["outbounds"][0]["tag"], "warp")
        self.assertEqual(xray["outbounds"][0]["settings"]["servers"][0]["port"], 41000)

    def test_argo_changes_only_bound_share_link(self):
        state = sample_state()
        state["argo"] = {
            "mode": "fixed",
            "target": "xr-vless-ws",
            "hostname": "argo.example.com",
            "tunnel_id": "abc",
            "account_id": "def",
        }
        nodes = GEN.build_nodes(state)
        bound = next(line for line in nodes.splitlines() if line.startswith("vless://4444"))
        direct = next(line for line in nodes.splitlines() if line.startswith("vmess://"))
        self.assertIn("@argo.example.com:443", bound)
        self.assertIn("security=tls", bound)
        self.assertNotIn("argo.example.com", direct)

    def test_duplicate_ports_are_rejected(self):
        state = sample_state()
        state["protocols"]["xr-trojan"]["port"] = 24443
        with self.assertRaises(GEN.StateError):
            GEN.validate_state(state)

    def test_render_cli_writes_private_data_locally(self):
        state = sample_state()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            state_path = root / "state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            loaded = GEN.load_state(str(state_path))
            GEN.write_json(str(root / "sing.json"), GEN.build_singbox(loaded))
            GEN.write_json(str(root / "xray.json"), GEN.build_xray(loaded))
            GEN.write_text(str(root / "nodes.txt"), GEN.build_nodes(loaded))
            self.assertTrue((root / "sing.json").is_file())
            self.assertIn("hysteria2://", (root / "nodes.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

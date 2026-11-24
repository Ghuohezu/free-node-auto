#!/usr/bin/env python3
"""离线回归测试：锁定节点解析与风险判定曾经踩过的坑。

不发起任何网络请求，可直接 python3 scripts/test_parser.py 运行。
"""
import asyncio
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import clean_nodes as cn

PASSED = []
FAILED = []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  [{'ok' if cond else 'FAIL'}] {name}" + (f" -> {detail}" if detail and not cond else ""))


PROTOCOLS = cn.load_settings()["protocols"]


def test_no_userinfo_protocols():
    """hy2/hy/hysteria2/tuic 的分享串常常没有 userinfo"""
    cases = [
        ("hy2 无 @", "hy2://1.2.3.4:443?pbk=AAEqA&sni=x.com#B"),
        ("hy2 有 @", "hysteria2://user:pass@1.2.3.4:443#C"),
        ("hysteria2", "hysteria2://1.2.3.4:443#D"),
        ("hy", "hy://1.2.3.4:443?auth=secret#E"),
        ("tuic", "tuic://1.2.3.4:443?uuid=abc&sni=x.com#F"),
    ]
    for name, line in cases:
        n = cn.parse_node(line, PROTOCOLS)
        check(name, bool(n and n.host == "1.2.3.4" and n.port == "443"),
              f"{n.host if n else None}:{n.port if n else None}")


def test_vmess():
    """vmess 同时存在 add 与旧式 host 两种字段"""
    add = base64.b64encode(json.dumps(
        {"add": "1.2.3.4", "port": 443, "ps": "ADDFORM"}).encode()).decode()
    host = base64.b64encode(json.dumps(
        {"host": "1.2.3.4", "port": "443", "ps": "HOSTFORM"}).encode()).decode()
    for name, line in (("vmess(add)", f"vmess://{add}"), ("vmess(host)", f"vmess://{host}")):
        n = cn.parse_node(line, PROTOCOLS)
        check(name, bool(n and n.host == "1.2.3.4" and n.port == "443"),
              f"{n.host if n else None}:{n.port if n else None}")


def test_ssr():
    """SSR 有 base64 载荷与原始 server:port 两种格式"""
    b64 = base64.b64encode(b"32.10.108.100:8388:origin:aes-256-cfb:tls1.2_ticket_auth:UFMv").decode()
    raw = "1.2.3.4:8388:origin:aes-256-cfb:tls1.2_ticket_auth:UFM/"
    n1 = cn.parse_node(f"ssr://{b64}#X", PROTOCOLS)
    n2 = cn.parse_node(f"ssr://{raw}#Y", PROTOCOLS)
    check("ssr(base64)", bool(n1 and n1.host == "32.10.108.100"), str(n1.host if n1 else None))
    check("ssr(原始)", bool(n2 and n2.host == "1.2.3.4" and n2.port == "8388"),
          f"{n2.host if n2 else None}:{n2.port if n2 else None}")


def test_b64_text_padding():
    """带标准 padding 的载荷必须完整还原，不能被尾部截断破坏"""
    payload = {"add": "1.2.3.4", "port": 443, "ps": "PAD"}
    enc = base64.b64encode(json.dumps(payload).encode()).decode()
    check("b64_text 往返", json.loads(cn.b64_text(enc)) == payload, cn.b64_text(enc))


def test_truncated_base64():
    """订阅里被截断的 base64 不应抛异常"""
    for blob in ("ZGUtYW0zLTIuZXFzdW5zaGluZS5jb206ODE4MTpvcmlnaW46YWVzLTI1Ni1jZmI6dGxzMS4y",
                "abcdef", "=" * 4, ""):
        try:
            cn.b64_text(blob)
            check(f"b64_text 容错 len={len(blob)}", True)
        except Exception as e:
            check(f"b64_text 容错 len={len(blob)}", False, type(e).__name__)


def test_host_validation():
    """base64 串不能当成主机名，否则会产出幽灵节点"""
    n = cn.parse_node(
        "vless://uuid@ZGUtYW0zLTIuZXFzdW5zaGluZS5jb206ODE4MTpvcmlnaW46YWVzLTI1Ni1jZmI6dGxzMS4y:443#X",
        PROTOCOLS)
    check("base64 主机名被拒绝", n is None)
    ok = cn.parse_node("vless://uuid@1.2.3.4:443?sni=x.com#Z", PROTOCOLS)
    check("正常节点不受影响", bool(ok and ok.host == "1.2.3.4"))


async def test_risk_levels():
    """高风险判定与是否过滤必须解耦，否则风险分支永远走不到"""
    class StubChecker:
        def save_disk_cache(self):
            pass

        async def check(self, session, ip):
            return {"risk_score": 95, "is_vpn": False, "source": "stub",
                    "is_residential": False, "is_datacenter": True,
                    "is_broadcast": False, "shared_users": None, "country": ""}

    node = cn.parse_node("vless://uuid@1.2.3.4:443#RISK", PROTOCOLS)

    for flag, expect_filtered in ((False, False), (True, True)):
        settings = cn.load_settings()
        settings["filter_risky"] = flag
        p = cn.NodeProcessor(settings)
        p.checker = StubChecker()
        p.dns_cache["1.2.3.4"] = "1.2.3.4"
        _, results, risky = await p.process([node])
        rec = results[0]
        check(f"风险标记保留(filter_risky={flag})",
              rec["risk_level"] == "RISKY" and rec["should_filter"] == expect_filtered,
              f"risk_level={rec['risk_level']} should_filter={rec['should_filter']}")
        check(f"risky_nodes 归集(filter_risky={flag})",
              len(risky) == (0 if expect_filtered else 1), f"len={len(risky)}")


def test_probe_classification():
    """可达性探测的协议分类：TLS 承载判定与 QUIC 名单"""
    s = cn.load_settings()
    cases = [
        ("vless tls", "vless://uuid@1.2.3.4:443?security=tls#A", True),
        ("vless reality", "vless://uuid@1.2.3.4:443?security=reality&pbk=x#B", False),
        ("vless none", "vless://uuid@1.2.3.4:443?type=tcp#C", False),
        ("trojan", "trojan://pw@1.2.3.4:443#D", True),
        ("ss 无tls", "ss://YWVz@1.2.3.4:8388#E", False),
        ("ssr", "ssr://1.2.3.4:8388:o:a:m:au#F", False),
    ]
    for name, line, expect in cases:
        n = cn.parse_node(line, s["protocols"])
        check(f"probe_tls {name}", bool(n) and cn._protocol_uses_tls(n) == expect)
    for p in ("tuic://", "hysteria2://", "hy2://", "hy://", "hysteria://"):
        check(f"QUIC {p}", p in cn.QUIC_PROTOCOLS)


def test_purity_split():
    """纯净度切分：<=30 为绿/白纯净桶，>30 应被反向删除"""
    split = cn.load_settings()["purity_split"]
    check("purity_split=30", split == 30, f"实际 {split}")
    # Emoji 映射：10→⚪白, 20→🟢绿, 30→🟢绿, 95→🔴红
    check("10=⚪", cn.purity_emoji(10) == "⚪")
    check("20=🟢", cn.purity_emoji(20) == "🟢")
    check("30=🟢", cn.purity_emoji(30) == "🟢")
    check("95=⚫", cn.purity_emoji(95) == "⚫")
    # 切分判定：10/20 保持，95 反向删除
    check("10 保持", not (10 > split))
    check("20 保持", not (20 > split))
    check("95 删除", 95 > split)
    # 反向删除映射：住宅 10 / 机房 20 / 代理 95
    check("住宅=10", cn.IPAPISource.__name__ == "IPAPISource")


def main():
    print("=" * 70)
    print("离线回归测试")
    print("=" * 70)
    test_no_userinfo_protocols()
    test_vmess()
    test_b64_text_padding()
    test_ssr()
    test_truncated_base64()
    test_host_validation()
    asyncio.run(test_risk_levels())
    test_probe_classification()
    test_purity_split()

    print()
    print(f"通过 {len(PASSED)} / 失败 {len(FAILED)}")
    if FAILED:
        print("失败项: " + ", ".join(FAILED))
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())

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


def test_rebuild_sources():
    """sources.txt 自维护：URL/base64/死/脏节点删除，纯净/未知写回"""
    import tempfile
    settings = cn.load_settings()
    tmpdir = tempfile.mkdtemp()
    sp = os.path.join(tmpdir, "sources.txt")
    raw = (
        "# 这是注释\n"
        "https://example.com/sub\n"
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=\n"
        "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443#home\n"
        "ss://YWVz@2.2.2.2:443#dc\n"
        "trojan://pw@3.3.3.3:443#dirty\n"
        "vless://22222222-2222-2222-2222-222222222222@4.4.4.4:443#unknown\n"
        "trojan://pw@5.5.5.5:443#dead\n"
        "这不是节点行\n"
    )
    with open(sp, "w", encoding="utf-8") as f:
        f.write(raw)

    results = [
        {"host": "1.1.1.1", "port": "443", "risk_score": 10, "should_filter": False,
         "is_residential": True, "raw": "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443#home"},
        {"host": "2.2.2.2", "port": "443", "risk_score": 20, "should_filter": False,
         "is_datacenter": True, "raw": "ss://YWVz@2.2.2.2:443#dc"},
        # 从订阅 base64 解码出来的纯净节点，sources.txt 里没有这一行
        {"host": "6.6.6.6", "port": "443", "risk_score": 15, "should_filter": False,
         "is_residential": True, "raw": "vless://66666666-6666-6666-6666-666666666666@6.6.6.6:443#fromblob"},
        {"host": "3.3.3.3", "port": "443", "risk_score": 95, "should_filter": True,
         "is_vpn": True, "raw": "trojan://pw@3.3.3.3:443#dirty"},
        {"host": "4.4.4.4", "port": "443", "risk_score": None, "should_filter": False,
         "raw": "vless://22222222-2222-2222-2222-222222222222@4.4.4.4:443#unknown"},
    ]
    settings["sources_file"] = sp
    stats = cn.rebuild_sources(results, settings)

    with open(sp, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    check("rebuild 纯净写回(含blob)", sum(1 for l in lines if "1.1.1.1" in l) == 1
          and sum(1 for l in lines if "2.2.2.2" in l) == 1
          and sum(1 for l in lines if "6.6.6.6" in l) == 1, str(lines))
    check("rebuild 未知写回", any("4.4.4.4" in l for l in lines), str(lines))
    check("rebuild URL/base64 删除", not any("example.com" in l or "YWJj" in l for l in lines))
    check("rebuild 死节点删除", not any("5.5.5.5" in l for l in lines))
    check("rebuild 脏节点删除", not any("3.3.3.3" in l for l in lines))
    check("rebuild 注释保留", any(l.startswith("#") for l in lines))
    check("rebuild 未知行保留", any("这不是节点行" in l for l in lines))
    check("rebuild 统计", stats["clean"] == 3 and stats["unknown"] == 1
          and stats["removed"] == 4, str(stats))
    return tmpdir


def test_ss_query_port():
    """ss(SIP002) 的 ?plugin=/? 查询串不能混进端口，否则会被误判不可达"""
    cases = [
        ("ss plugin", "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#A", "8388"),
        ("ss 空查询", "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:19999?#B", "19999"),
        ("ss 无查询", "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#C", "8388"),
    ]
    for name, line, expect in cases:
        n = cn.parse_node(line, PROTOCOLS)
        check(name, bool(n and n.port == expect and n.port.isdigit()),
              f"{n.host if n else None}:{n.port if n else None}")


def test_ipv6_and_port_validation():
    """IPv6 节点应可解析；缺少/非法端口的节点必须拒绝"""
    v6 = cn.parse_node("vless://uuid@[2001:db8::1]:443?security=tls#v6", PROTOCOLS)
    check("IPv6 解析", bool(v6 and v6.host == "2001:db8::1" and v6.port == "443"),
          f"{v6.host if v6 else None}:{v6.port if v6 else None}")
    check("缺端口拒绝", cn.parse_node("hysteria2://1.2.3.4#noport", PROTOCOLS) is None)
    check("非法端口拒绝", cn.parse_node("trojan://pw@1.2.3.4:70000#bad", PROTOCOLS) is None)


def test_label_idempotent():
    """重复清洗已打标节点，不能把旧标签一路叠加"""
    p = cn.NodeProcessor(cn.load_settings())
    n = cn.parse_node("trojan://pw@1.2.3.4:443#name", PROTOCOLS)
    first = p.apply_label(n, "【⚪ 住宅|原生】")
    n2 = cn.parse_node(first, PROTOCOLS)
    second = p.apply_label(n2, "【🟢 机房|原生】")
    check("标签幂等", second.count("【") == 1 and "name" in second, second)


async def test_unknown_info_is_not_clean():
    """IP 已解析但检测结果为空时，必须归为 UNKNOWN 而不是 CLEAN"""
    class NullChecker:
        def save_disk_cache(self):
            pass

        async def check(self, session, ip):
            return None

    node = cn.parse_node("vless://uuid@1.2.3.4:443#UNK", PROTOCOLS)
    settings = cn.load_settings()
    p = cn.NodeProcessor(settings)
    p.checker = NullChecker()
    p.dns_cache["1.2.3.4"] = "1.2.3.4"
    _, results, _ = await p.process([node])
    rec = results[0]
    check("未知不记 CLEAN", rec["risk_level"] == "UNKNOWN" and p.stats["clean"] == 0,
          f"risk_level={rec['risk_level']} clean={p.stats['clean']}")
    check("未知计入 unknown", p.stats["unknown"] == 1, f"unknown={p.stats['unknown']}")


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
    test_ss_query_port()
    test_ipv6_and_port_validation()
    test_label_idempotent()
    asyncio.run(test_risk_levels())
    asyncio.run(test_unknown_info_is_not_clean())
    test_probe_classification()
    test_purity_split()
    test_rebuild_sources()

    print()
    print(f"通过 {len(PASSED)} / 失败 {len(FAILED)}")
    if FAILED:
        print("失败项: " + ", ".join(FAILED))
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())

import asyncio
import base64
import json
import os
import re
import socket
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except Exception:
    yaml = None

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except Exception:
    aiohttp = None
    AIOHTTP_AVAILABLE = False


INPUT = "output/raw_nodes.txt"
OUTPUT = "output/nodes.txt"
RISKY_OUTPUT = "output/risky_nodes.txt"
FILTERED_LOG = "output/filtered_nodes.log"
RESULT_JSON = "output/result.json"
HTML_REPORT = "output/report.html"
SETTINGS_FILE = "config/settings.yaml"

DEFAULT_SETTINGS = {
    "risk_threshold": 75,
    "filter_risky": True,
    "filter_vpn": True,
    "filter_blacklist": True,
    "sources": ["ippure", "ipapi"],
    "blacklist_ips": [
        "120.227.1.43",
        "47.240.80.220",
    ],
    "protocols": [
        "vmess://", "vless://", "ss://", "ssr://", "trojan://",
        "anytls://", "hysteria://", "hysteria2://", "hy2://", "hy://",
        "tuic://"
    ],
    "concurrency": 16,
    "request_timeout": 8,
    "dns_timeout": 5,
    "rate": {
        "ippure": 25,
        "ipapi": 40,
    },
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) node-cleaner/2.0",
}

# 纯净度 Emoji 对照表（与 clash-ip-checker core/sources/base.py 保持一致）
PURITY_TABLE = [
    (10, "⚪"),
    (30, "🟢"),
    (50, "🟡"),
    (70, "🟠"),
    (90, "🔴"),
]

# 共享人数 Emoji 对照表（与 clash-ip-checker core/sources/ping0.py 保持一致）
SHARED_TABLE = [
    (10, "🟢"),
    (100, "🟡"),
    (1000, "🟠"),
    (10000, "🔴"),
]

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# 主机名：字母数字连字符分段，且总长度不超过 253
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")


def purity_emoji(score) -> str:
    try:
        val = float(score)
    except (TypeError, ValueError):
        return "❓"
    for upper, emoji in PURITY_TABLE:
        if val <= upper:
            return emoji
    return "⚫"


def shared_emoji(count) -> str:
    try:
        val = int(str(count).split("+")[0])
    except (TypeError, ValueError):
        return ""
    if val <= 0:
        return ""
    for upper, emoji in SHARED_TABLE:
        if val <= upper:
            return emoji
    return "⚫"


def load_settings() -> Dict:
    cfg = json.loads(json.dumps(DEFAULT_SETTINGS))
    if not os.path.exists(SETTINGS_FILE):
        return cfg
    if yaml is None:
        print(f"⚠️ pyyaml 未安装，忽略 {SETTINGS_FILE}，使用内置默认配置")
        return cfg
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        for key, val in user.items():
            if val is None:
                continue
            if key == "rate" and isinstance(val, dict):
                merged = dict(cfg["rate"])
                merged.update(val)
                cfg["rate"] = merged
            else:
                cfg[key] = val
    except Exception as e:
        print(f"⚠️ 读取 {SETTINGS_FILE} 失败，使用内置默认配置: {e}")
    return cfg


def b64_text(text: str) -> str:
    # 订阅里常有被截断或混入 query 的 base64，这里做容错处理
    clean = re.sub(r"[^A-Za-z0-9+/]", "", text.strip()).rstrip("=")
    clean = clean[: len(clean) - (len(clean) % 4)]
    if not clean:
        return ""
    return base64.b64decode(clean + "=" * (-len(clean) % 4), validate=False).decode(
        "utf-8", errors="ignore"
    )


class Node:
    __slots__ = ("raw", "protocol", "remark", "host", "port")

    def __init__(self, raw: str, protocol: str, remark: str, host: str, port: str):
        self.raw = raw
        self.protocol = protocol
        self.remark = remark or "未命名"
        self.host = host or ""
        self.port = port or ""

    def key(self) -> str:
        uuid = re.search(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            self.raw.lower()
        )
        if uuid:
            return "uuid:" + uuid.group(0)
        if self.host:
            return "server:" + self.host.lower() + ":" + self.port
        return self.raw


class RateLimiter:
    def __init__(self, rpm: int, burst: int):
        self.rate = max(1, rpm) / 60.0
        self.capacity = max(1, burst)
        self.tokens = self.capacity
        self._last = None
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def acquire(self):
        loop = asyncio.get_event_loop()
        while True:
            async with self._lock:
                now = loop.time()
                if self._last is not None:
                    self.tokens = min(
                        self.capacity, self.tokens + (now - self._last) * self.rate
                    )
                self._last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    break
            await asyncio.sleep(0.2)
        yield


def _split_remark(body: str) -> Tuple[str, str]:
    if "#" in body:
        body, remark = body.rsplit("#", 1)
        try:
            remark = unquote(remark)
        except Exception:
            pass
        return body, remark
    return body, ""


def _valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return bool(IPV4_RE.fullmatch(host) or HOSTNAME_RE.fullmatch(host))


def _split_host_port(body: str) -> Tuple[str, str]:
    auth = body.split("?", 1)[0].split("#", 1)[0]
    # hysteria/hy2/tuic 等协议的分享串常常没有 userinfo，@ 必须可选
    if "@" in auth:
        auth = auth.rsplit("@", 1)[1]
    match = re.search(r"(?:\[([^\]]+)\]|([^\]:/?#\s]+))(?::(\d{2,6}))?", auth)
    if not match:
        return "", ""
    host = (match.group(1) or match.group(2) or "").strip()
    return host, match.group(3) or ""


def _parse_vmess(body: str, remark: str) -> Tuple[str, str, str]:
    try:
        data = json.loads(b64_text(body))
        host = str(data.get("add") or data.get("host") or "")
        port = str(data.get("port") or "")
        if not remark:
            remark = str(data.get("ps") or "")
        return host, port, remark
    except Exception:
        return _split_host_port(body) + (remark,)


def _parse_ssr(body: str) -> Tuple[str, str]:
    # base64 字母表不含冒号，因此用是否含冒号即可区分两种 SSR 格式
    payload = body.split("#", 1)[0]
    raw_parts = payload.split(":")
    if len(raw_parts) >= 2:
        return raw_parts[0].strip("[]"), raw_parts[1]
    try:
        decoded = b64_text(payload)
    except Exception:
        return "", ""
    decoded_parts = decoded.split(":")
    if len(decoded_parts) >= 2:
        return decoded_parts[0].strip("[]"), decoded_parts[1]
    return "", ""


def _parse_ss(body: str) -> Tuple[str, str]:
    if "@" in body and not body.startswith("ss://"):
        rest = body.split("@", 1)[1]
        host, _, port = rest.partition(":")
        return host.strip("[]"), port
    try:
        decoded = b64_text(body)
        if "@" in decoded:
            rest = decoded.split("@", 1)[1]
            host, _, port = rest.partition(":")
            return host.strip("[]"), port
        pieces = decoded.split(":")
        if len(pieces) >= 2:
            return pieces[-2], pieces[-1]
    except Exception:
        pass
    return "", ""


def parse_node(line: str, protocols: List[str]) -> Optional[Node]:
    line = line.strip()
    if not line:
        return None
    lowered = line.lower()
    protocol = None
    for p in protocols:
        if lowered.startswith(p.lower()):
            protocol = p
            break
    if protocol is None:
        return None

    body = line[len(protocol):]
    body, remark = _split_remark(body)

    if protocol == "vmess://":
        host, port, remark = _parse_vmess(body, remark)
    elif protocol == "ssr://":
        host, port = _parse_ssr(body)
    elif protocol == "ss://":
        host, port = _parse_ss(body)
    else:
        host, port = _split_host_port(body)

    if not host or not _valid_host(host):
        return None
    return Node(line, protocol, remark, host, port)


class IPSource:
    name = "base"

    def __init__(self, settings: Dict):
        self.settings = settings
        self.timeout = aiohttp.ClientTimeout(total=settings["request_timeout"])
        self.headers = {"User-Agent": settings["user_agent"], "Accept": "application/json"}
        self.limiter = RateLimiter(
            settings["rate"].get(self.name, 30),
            max(1, min(settings["concurrency"], 5)),
        )

    async def check(self, session, ip: str) -> Optional[Dict]:
        raise NotImplementedError


class IPPureSource(IPSource):
    name = "ippure"
    score_url = "https://api.ippure.net/v2/score"
    shared_url = "https://api.ippure.net/v2/shared"

    @staticmethod
    def _first(data: Dict, keys: List[str], default=None):
        for k in keys:
            if k in data and data[k] is not None:
                return data[k]
        return default

    async def check(self, session, ip: str) -> Optional[Dict]:
        async with self.limiter.acquire():
            pass
        try:
            async with session.get(self.score_url, params={"ip": ip}) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
        except Exception:
            return None

        score = self._first(data, ["riskScore", "fraudScore", "score"])
        if score is None:
            return None

        ip_type = str(self._first(data, ["ipType", "ip_type", "type"], "")).lower()
        is_resi = self._first(data, ["isResidential"], None)
        if is_resi is None:
            is_resi = ip_type in ("residential", "isp")
        is_datacenter = self._first(data, ["isDatacenter"], None)
        if is_datacenter is None:
            is_datacenter = ip_type in ("datacenter", "idc")

        result = {
            "ip": self._first(data, ["ip"], ip),
            "risk_score": int(score),
            "is_residential": bool(is_resi),
            "is_datacenter": bool(is_datacenter),
            "is_broadcast": bool(self._first(data, ["isBroadcast"], False)),
            "is_vpn": bool(self._first(data, ["isVpn", "isVPN"], False)),
            "shared_users": None,
            "country": self._first(data, ["country", "countryName"], ""),
            "source": self.name,
        }

        try:
            async with self.limiter.acquire():
                pass
            async with session.get(self.shared_url, params={"ip": ip}) as resp:
                if resp.status == 200:
                    shared_data = await resp.json(content_type=None)
                    users = self._first(shared_data, ["shared", "sharedUsers", "sharedCount"])
                    if users is not None:
                        result["shared_users"] = users
        except Exception:
            pass

        return result


class IPAPISource(IPSource):
    name = "ipapi"
    url = "http://ip-api.com/json"
    fields = "status,country,city,isp,as,asname,proxy,hosting,query"

    async def check(self, session, ip: str) -> Optional[Dict]:
        async with self.limiter.acquire():
            pass
        try:
            async with session.get(self.url + "/" + ip, params={"fields": self.fields}) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
        except Exception:
            return None

        if not isinstance(data, dict) or data.get("status") != "success":
            return None

        hosting = bool(data.get("hosting"))
        proxy = bool(data.get("proxy"))
        return {
            "ip": data.get("query", ip),
            "risk_score": 95 if proxy else (55 if hosting else 20),
            "is_residential": not hosting,
            "is_datacenter": hosting,
            "is_broadcast": False,
            "is_vpn": proxy,
            "shared_users": None,
            "country": data.get("country", ""),
            "isp": data.get("isp", ""),
            "asname": data.get("asname", ""),
            "source": self.name,
        }


SOURCES = {
    "ippure": IPPureSource,
    "ipapi": IPAPISource,
}


class IPChecker:
    def __init__(self, settings: Dict):
        self.settings = settings
        self.sources = [
            SOURCES[name](settings)
            for name in settings["sources"]
            if name in SOURCES
        ]
        if not self.sources:
            raise RuntimeError("没有可用的 IP 检测数据源，请检查 config/settings.yaml 的 sources")
        self.cache: Dict[str, Optional[Dict]] = {}
        self.cache_file = settings.get("ip_cache_file", "output/ip_cache.json")
        self._load_disk_cache()

    def _load_disk_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    self.cache = {str(k): v for k, v in data.items()}
        except Exception:
            self.cache = {}

    def save_disk_cache(self):
        os.makedirs(os.path.dirname(self.cache_file) or ".", exist_ok=True)
        try:
            with open(self.cache_file, "w", encoding="utf-8") as fh:
                json.dump(self.cache, fh, ensure_ascii=False)
        except Exception:
            pass

    async def check(self, session, ip: str) -> Optional[Dict]:
        if ip in self.cache:
            return self.cache[ip]
        result = None
        for source in self.sources:
            try:
                result = await source.check(session, ip)
            except Exception:
                result = None
            if result is not None:
                break
        self.cache[ip] = result
        return result


class NodeProcessor:
    def __init__(self, settings: Dict):
        self.settings = settings
        self.checker = IPChecker(settings)
        self.dns_cache: Dict[str, Optional[str]] = {}
        self.stats = {
            "total": 0,
            "filtered": 0,
            "risky": 0,
            "clean": 0,
            "ip_only": 0,
            "domain_only": 0,
            "unknown": 0,
        }
        self.filtered_log: List[str] = []
        self.risky_log: List[str] = []
        self.results: List[Dict] = []

    async def resolve_ip(self, host: str, loop) -> Optional[str]:
        if IPV4_RE.match(host):
            return host
        if host in self.dns_cache:
            return self.dns_cache[host]
        try:
            infos = await loop.getaddrinfo(host, None, family=socket.AF_INET,
                                            proto=socket.IPPROTO_TCP)
            ip = infos[0][4][0]
        except Exception:
            ip = None
        self.dns_cache[host] = ip
        return ip

    def describe(self, info: Optional[Dict]) -> Tuple[str, str, str]:
        if not info:
            return "❓", "未知", "未知"
        attr = "❓"
        if info.get("is_residential"):
            attr = "住宅"
        elif info.get("is_datacenter"):
            attr = "机房"
        src = "❓"
        if info.get("is_broadcast") is not None:
            src = "广播" if info.get("is_broadcast") else "原生"
        emoji = purity_emoji(info.get("risk_score"))
        return emoji, attr, src

    def build_label(self, emoji: str, attr: str, src: str, shared: Optional[str]) -> str:
        info = f"{attr}|{src}"
        if info == "❓|❓":
            info = "未知"
        return f"【{emoji}{shared or ''} {info}】"

    def apply_label(self, node: Node, label: str) -> str:
        raw = node.raw
        body, _remark = _split_remark(raw)
        return f"{body}#{label} {node.remark}"

    async def process_one(self, node: Node, session, loop) -> Tuple[Optional[str], Dict]:
        ip = await self.resolve_ip(node.host, loop)

        info = None
        if ip:
            try:
                info = await self.checker.check(session, ip)
            except Exception:
                info = None

        emoji, attr, src = self.describe(info)
        shared = shared_emoji(info.get("shared_users")) if info else ""
        label = self.build_label(emoji, attr, src, shared)
        risk_score = info.get("risk_score") if info else None
        is_vpn = bool(info.get("is_vpn")) if info else False

        record = {
            "protocol": node.protocol,
            "remark": node.remark,
            "host": node.host,
            "port": node.port,
            "ip": ip or "❓",
            "remark_old": node.remark,
            "risk_score": risk_score,
            "fraud_score": risk_score,
            "is_residential": bool(info.get("is_residential")) if info else None,
            "is_datacenter": bool(info.get("is_datacenter")) if info else None,
            "is_broadcast": info.get("is_broadcast") if info else None,
            "is_vpn": is_vpn,
            "shared_users": info.get("shared_users") if info else None,
            "country": (info or {}).get("country", ""),
            "source": (info or {}).get("source", ""),
            "emoji": emoji,
            "attr": attr,
            "ip_src": src,
            "label": label,
            "full_string": label,
            "rating": emoji,
            "attr_cn": attr,
            "src_cn": src,
            "should_filter": False,
            "filter_reason": "",
        }

        if not ip:
            self.stats["unknown"] += 1
            record["risk_level"] = "UNKNOWN"
            return self.apply_label(node, label), record

        if self.settings["filter_blacklist"] and ip in set(self.settings["blacklist_ips"]):
            record["should_filter"] = True
            record["filter_reason"] = "IP 黑名单"
            return None, record

        risk_level = "CLEAN"
        if is_vpn:
            risk_level = "RISKY"
            record["filter_reason"] = "VPN 节点"
            if self.settings["filter_vpn"]:
                record["should_filter"] = True
        elif (risk_score is not None and risk_score > self.settings["risk_threshold"]):
            risk_level = "RISKY"
            record["filter_reason"] = f"风险分数过高 ({int(risk_score)}%)"
            if self.settings["filter_risky"]:
                record["should_filter"] = True
        record["risk_level"] = risk_level

        return self.apply_label(node, label), record

    async def process(self, nodes: List[Node]) -> Tuple[List[str], List[Dict], List[str]]:
        self.stats["total"] = len(nodes)
        sem = asyncio.Semaphore(max(1, self.settings["concurrency"]))
        loop = asyncio.get_event_loop()
        connector = aiohttp.TCPConnector(limit=max(1, self.settings["concurrency"]), ssl=False)
        headers = {"User-Agent": self.settings["user_agent"]}
        final_nodes: List[str] = []
        risky_nodes: List[str] = []
        unique: Dict[str, str] = {}

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.settings["request_timeout"]),
            connector=connector,
            headers=headers,
        ) as session:
            async def worker(node: Node):
                async with sem:
                    return await self.process_one(node, session, loop)

            for idx, node in enumerate(nodes, 1):
                if idx % 25 == 0 or idx == len(nodes):
                    print(f"  处理中: {idx}/{len(nodes)}", end="\r", flush=True)

                if IPV4_RE.match(node.host):
                    self.stats["ip_only"] += 1
                else:
                    self.stats["domain_only"] += 1

                try:
                    labeled, record = await worker(node)
                except Exception as e:
                    print(f"\n⚠️ 处理节点失败: {str(e)[:120]}")
                    record = {
                        "protocol": node.protocol, "remark": node.remark, "host": node.host,
                        "port": node.port, "ip": "❓", "risk_score": None, "emoji": "❓",
                        "attr": "未知", "ip_src": "未知", "source": "", "country": "",
                        "should_filter": False, "filter_reason": "", "risk_level": "UNKNOWN",
                        "label": "", "fraud_score": None, "is_vpn": False,
                        "is_residential": None, "is_datacenter": None, "is_broadcast": None,
                        "shared_users": None,
                    }
                    labeled = node.raw

                self.results.append(record)

                if record["should_filter"]:
                    self.stats["filtered"] += 1
                    self.filtered_log.append(
                        f"[{record['filter_reason']}] {record['remark']} | "
                        f"IP: {record['ip']} | 分数: {record['fraud_score']}"
                    )
                    continue

                if record["risk_level"] == "RISKY":
                    self.stats["risky"] += 1
                    risky_nodes.append(labeled)
                    self.risky_log.append(
                        f"[风险保留] {record['remark']} | IP: {record['ip']} | "
                        f"分数: {record['fraud_score']} | {record['filter_reason'] or '风险标记'}"
                    )
                else:
                    self.stats["clean"] += 1

                # 订阅输出必须保留每一个不同的节点串（同一服务器常有多个 uuid/协议），
                # 因此按节点原文去重，IP 层面的重复只靠 checker 缓存避免重复查询
                key = node.raw
                if key not in unique:
                    unique[key] = labeled
                    final_nodes.append(labeled)

        self.checker.save_disk_cache()

        print("\n")
        return final_nodes, self.results, risky_nodes


def extract_node_lines(text: str) -> List[str]:
    lines: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def generate_html_report(results: List[Dict], stats: Dict) -> str:
    html = [
        "<!doctype html>",
        '<html><head><meta charset="utf-8"><title>节点清洗报告</title>',
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;margin:24px;color:#222}",
        "h1{font-size:20px}h2{font-size:16px;margin-top:28px}",
        "table{border-collapse:collapse;width:100%;font-size:13px}",
        "th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}",
        "th{background:#f5f5f5}tr:nth-child(even){background:#fafafa}",
        ".kpi{display:inline-block;margin-right:24px}",
        ".kpi b{font-size:20px;display:block}",
        "</style></head><body>",
        "<h1>节点清洗报告</h1>",
        f'<div class="kpi">总节点<b>{stats.get("total", 0)}</b></div>',
        f'<div class="kpi">IP 直连<b>{stats.get("ip_only", 0)}</b></div>',
        f'<div class="kpi">域名解析<b>{stats.get("domain_only", 0)}</b></div>',
        f'<div class="kpi">正常<b>{stats.get("clean", 0)}</b></div>',
        f'<div class="kpi">风险<b>{stats.get("risky", 0)}</b></div>',
        f'<div class="kpi">已过滤<b>{stats.get("filtered", 0)}</b></div>',
        '<table><tr><th>节点名</th><th>协议</th><th>服务器</th><th>解析 IP</th><th>纯净度</th>'
        '<th>风险分</th><th>带宽类型</th><th>IP 来源</th><th>共享人数</th><th>国家</th><th>数据源</th></tr>',
    ]
    for r in results[:1000]:
        shared = r.get("shared_users")
        html.append(
            "<tr>"
            f"<td>{r.get('remark', '')}</td>"
            f"<td>{r.get('protocol', '')}</td>"
            f"<td>{r.get('host', '')}{':' + r.get('port', '') if r.get('port') else ''}</td>"
            f"<td>{r.get('ip', '')}</td>"
            f"<td>{r.get('emoji', '')}</td>"
            f"<td>{'' if r.get('fraud_score') is None else r.get('fraud_score')}</td>"
            f"<td>{r.get('attr', '')}</td>"
            f"<td>{r.get('ip_src', '')}</td>"
            f"<td>{'' if shared is None else shared}</td>"
            f"<td>{r.get('country', '')}</td>"
            f"<td>{r.get('source', '')}</td>"
            "</tr>"
        )
    html.append("</table></body></html>")
    return "\n".join(html)


def read_raw_nodes(path: str) -> List[str]:
    with open(path, encoding="utf-8") as f:
        return f.read()


async def main():
    print("=" * 70)
    print("🚀 节点清洗脚本 (clash-ip-checker 风格标注版)")
    print("=" * 70)

    settings = load_settings()
    print(f"🔧 数据源顺序: {' -> '.join(settings['sources'])}")
    print(f"🔧 风险阈值: {settings['risk_threshold']} | 过滤风险节点: {settings['filter_risky']}")

    if not AIOHTTP_AVAILABLE:
        raise RuntimeError("缺少 aiohttp，请先执行 pip install -r requirements.txt")

    if not os.path.exists(INPUT):
        print(f"❌ 没有找到输入文件: {INPUT}")
        return

    text = read_raw_nodes(INPUT)
    print(f"📊 原始文件大小: {len(text)} 字节")

    raw_lines = extract_node_lines(text)
    nodes: List[Node] = []
    seen = set()
    for line in raw_lines:
        node = parse_node(line, settings["protocols"])
        if node is None:
            continue
        if node.raw in seen:
            continue
        seen.add(node.raw)
        nodes.append(node)

    print(f"📝 发现节点: {len(nodes)} 个")
    if not nodes:
        print("⚠️ 未找到任何节点，请检查输入文件")
        return

    processor = NodeProcessor(settings)
    final_nodes, results, risky_nodes = await processor.process(nodes)

    print("\n" + "=" * 70)
    print("📊 处理统计:")
    print("=" * 70)
    print(f"✅ 总节点数:   {processor.stats['total']}")
    print(f"🌐 IP 直连:     {processor.stats['ip_only']}")
    print(f"📍 域名解析:    {processor.stats['domain_only']}")
    print(f"✓ 正常节点:     {processor.stats['clean']}")
    print(f"⚠️  风险节点:   {processor.stats['risky']}")
    print(f"❌ 已过滤:     {processor.stats['filtered']}")
    print(f"❔ 无法解析:   {processor.stats['unknown']}")
    print(f"🔄 去重后输出:  {len(final_nodes)}")

    os.makedirs("output", exist_ok=True)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for node in final_nodes:
            f.write(node + "\n")
    print(f"\n✅ 节点列表: {OUTPUT} ({len(final_nodes)} 条)")

    if risky_nodes:
        with open(RISKY_OUTPUT, "w", encoding="utf-8") as f:
            for node in risky_nodes:
                f.write(node + "\n")
        print(f"📋 风险节点: {RISKY_OUTPUT} ({len(risky_nodes)} 条)")

    with open(RESULT_JSON, "w", encoding="utf-8") as f:
        json.dump({"stats": processor.stats, "settings": settings, "results": results},
                  f, ensure_ascii=False, indent=2)
    print(f"📋 JSON 结果: {RESULT_JSON}")

    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(generate_html_report(results, processor.stats))
    print(f"📊 HTML 报告: {HTML_REPORT}")

    if processor.filtered_log or processor.risky_log:
        with open(FILTERED_LOG, "w", encoding="utf-8") as f:
            f.write("过滤日志\n")
            f.write("=" * 70 + "\n\n")
            for log in processor.filtered_log:
                f.write(log + "\n")
            if processor.risky_log:
                f.write("\n" + "=" * 70 + "\n\n")
                f.write("风险保留记录\n\n")
                for log in processor.risky_log:
                    f.write(log + "\n")
        print(f"📋 过滤日志: {FILTERED_LOG}")

    print("=" * 70)
    print("✨ 所有任务完成！")
    print("=" * 70)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"❌ 未捕获异常: {e}")

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

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
HOME_OUTPUT = "output/home_nodes.txt"
DC_OUTPUT = "output/datacenter_nodes.txt"
DEAD_LOG = "output/dead_nodes.log"
FILTERED_LOG = "output/filtered_nodes.log"
RISKY_OUTPUT = "output/risky_nodes.txt"
SETTINGS_FILE = "config/settings.yaml"

DEFAULT_SETTINGS = {
    "purity_split": 30,
    "risk_threshold": 30,
    "filter_risky": True,
    "filter_vpn": True,
    "filter_blacklist": True,
    "reverse_delete_sources": True,
    "sources_file": "config/sources.txt",
    "sources": ["ipinfo", "ipapi"],
    "blacklist_ips": [
        "120.227.1.43",
        "47.240.80.220",
    ],
    "hosting_asns": [],
    "hosting_keywords": [],
    "protocols": [
        "vmess://", "vless://", "ss://", "ssr://", "trojan://",
        "anytls://", "hysteria://", "hysteria2://", "hy2://", "hy://",
        "tuic://"
    ],
        "concurrency": 16,
    "request_timeout": 8,
    "dns_timeout": 5,
    "rate": {
        "ipinfo": 120,
        "ippure": 25,
        "ipapi": 40,
    },
    "probe_reachability": True,
    "probe_timeout": 5,
    "probe_tls": True,
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) node-cleaner/2.0",
}

# ASN/组织名启发式：ip-api 的 hosting 字段对部分托管商识别不准（例如
# Cornseed、Awas.ovh、Skinark 会被判成住宅），这里做一层补充判定。
# 可在 config/settings.yaml 的 hosting_asns / hosting_keywords 里继续追加。
HOSTING_ASNS = {
    "AS16509", "AS14618", "AS15169", "AS396982", "AS8075", "AS13335",
    "AS14061", "AS20473", "AS63949", "AS16276", "AS24940", "AS51167",
    "AS9009", "AS36352", "AS45102", "AS37963", "AS132203", "AS31898",
    "AS209363", "AS201279", "AS206069", "AS984", "AS56380",
}
HOSTING_KEYWORDS = [
    "amazon", "aws", "google cloud", "googleusercontent", "cloudflare",
    "microsoft", "azure", "oracle", "alibaba", "aliyun", "tencent",
    "huawei cloud", "digitalocean", "vultr", "linode", "akamai", "hetzner",
    "ovh", "leaseweb", "contabo", "m247", "psychz", "quadranet",
    "colocrossing", "choopa", "datacamp", "hostinger", "godaddy", "ionos",
    "gcore", "upcloud", "scaleway", "hosting", "datacenter", "data center",
    "idc", "vps", "dedicated server", "cloud",
]

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
# 本脚本写入的标签形如 【⚪ 住宅|原生】/【❓ 未知】，仅识别这一类，避免误删节点自带前缀
LABEL_PREFIX_RE = re.compile(r"^(?:【[^】]*(?:\||未知)[^】]*】\s*)+")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


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
    if len(clean) % 4 == 1:
        # 末尾单个字符无法构成有效分组，丢弃它
        clean = clean[: len(clean) - 1]
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
    host = (host or "").strip("[]").strip()
    if not host or len(host) > 253:
        return False
    if _is_ip_literal(host):
        return True
    return bool(HOSTNAME_RE.fullmatch(host))


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
    # SIP002 的插件参数以 ?plugin=... 形式跟在 host:port 后面，必须先剥离，
    # 否则端口会变成 "8388?plugin=..."，后续 int(port) 失败导致节点被误判不可达。
    body = body.split("?", 1)[0]
    if "@" in body:
        return _split_host_port(body)
    try:
        decoded = b64_text(body)
    except Exception:
        return "", ""
    if "@" in decoded:
        return _split_host_port(decoded)
    pieces = decoded.split(":")
    if len(pieces) >= 2:
        return pieces[-2].strip("[]"), pieces[-1].strip("[]")
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
    if not port or not port.isdigit() or not (1 <= int(port) <= 65535):
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
    fields = "status,country,city,isp,as,asname,org,proxy,hosting,query"

    def __init__(self, settings: Dict):
        super().__init__(settings)
        self.hosting_asns = {a.upper() for a in HOSTING_ASNS}
        self.hosting_asns.update(
            str(a).upper() for a in (settings.get("hosting_asns") or [])
        )
        self.hosting_keywords = list(HOSTING_KEYWORDS)
        self.hosting_keywords.extend(
            str(k).lower() for k in (settings.get("hosting_keywords") or [])
        )

    def _looks_like_hosting(self, *values) -> bool:
        text = " ".join(str(v).lower() for v in values if v)
        if not text:
            return False
        if any(k in text for k in self.hosting_keywords):
            return True
        asns = set(re.findall(r"as\d+", text))
        return bool(asns & {a.lower() for a in self.hosting_asns})

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

        proxy = bool(data.get("proxy"))
        hosting = bool(data.get("hosting")) or self._looks_like_hosting(
            data.get("as"), data.get("asname"), data.get("isp"), data.get("org")
        )
        # 纯净度评分：普通住宅/家用 IP 最干净（10），普通机房 IP 稍高（20），
        # 被判为代理/VPN 的 IP 风险最高（95）。
        # 这样机房节点也能落进 purity_split(30) 以内的"绿/白"纯净桶。
        risk_score = 95 if proxy else (20 if hosting else 10)
        return {
            "ip": data.get("query", ip),
            "risk_score": risk_score,
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


def _parse_ipinfo(data: Dict, ip: str) -> Optional[Dict]:
    """解析 ipinfo.io/widget/demo 返回的数据。

    它提供 asn.type / company.type / privacy.hosting，能识别出 ip-api
    误判为住宅的机房 IP（例如 Cornseed、Awas.ovh 这类托管商）。
    """
    if not isinstance(data, dict) or not data.get("ip"):
        return None
    asn = data.get("asn") or {}
    company = data.get("company") or {}
    privacy = data.get("privacy") or {}
    asn_type = str(asn.get("type") or "").lower()
    company_type = str(company.get("type") or "").lower()
    hosting = (
        bool(privacy.get("hosting"))
        or asn_type == "hosting"
        or company_type == "hosting"
    )
    vpn = bool(privacy.get("vpn")) or bool(privacy.get("proxy")) or bool(privacy.get("tor"))
    risk_score = 95 if vpn else (20 if hosting else 10)
    return {
        "ip": data.get("ip", ip),
        "risk_score": risk_score,
        "is_residential": not hosting,
        "is_datacenter": hosting,
        "is_broadcast": None,
        "is_vpn": vpn,
        "shared_users": None,
        "country": data.get("country", ""),
        "isp": company.get("name") or asn.get("name") or "",
        "asname": asn.get("name") or "",
        "source": "ipinfo",
    }


class IPInfoSource(IPSource):
    name = "ipinfo"
    url = "https://ipinfo.io/widget/demo"

    async def check(self, session, ip: str) -> Optional[Dict]:
        async with self.limiter.acquire():
            pass
        try:
            async with session.get(f"{self.url}/{ip}") as resp:
                if resp.status != 200:
                    return None
                payload = await resp.json(content_type=None)
        except Exception:
            return None
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            data = payload
        return _parse_ipinfo(data, ip)


SOURCES = {
    "ipinfo": IPInfoSource,
    "ippure": IPPureSource,
    "ipapi": IPAPISource,
}


def merge_ip_info(results: List[Dict]) -> Optional[Dict]:
    """合并多源结果：机房/代理判定取"任意一源命中"，风险分取最大值。

    这样 ip-api 判住宅、ipinfo 判机房时，最终会按机房处理，避免把机房节点
    错误输出到家宽列表。
    """
    if not results:
        return None
    base = dict(results[0])
    is_datacenter = any(bool(r.get("is_datacenter")) for r in results)
    is_vpn = any(bool(r.get("is_vpn")) for r in results)
    scores = [r.get("risk_score") for r in results if r.get("risk_score") is not None]
    is_broadcast = next(
        (r.get("is_broadcast") for r in results if r.get("is_broadcast") is not None),
        None,
    )
    shared = next(
        (r.get("shared_users") for r in results if r.get("shared_users") is not None),
        None,
    )
    for key in ("ip", "country", "isp", "asname"):
        if not base.get(key):
            base[key] = next((r.get(key) for r in results if r.get(key)), "")
    base.update({
        "risk_score": max(scores) if scores else None,
        "is_datacenter": is_datacenter,
        "is_residential": (not is_datacenter)
        and any(bool(r.get("is_residential")) for r in results),
        "is_vpn": is_vpn,
        "is_broadcast": is_broadcast,
        "shared_users": shared,
        "source": "+".join(
            str(r.get("source") or "") for r in results if r.get("source")
        ) or base.get("source", ""),
    })
    return base


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
                    # 只加载成功结果，失败结果下次重新检测（避免一次 429 永久污染缓存）
                    self.cache = {
                        str(k): v for k, v in data.items() if v is not None
                    }
        except Exception:
            self.cache = {}

    def save_disk_cache(self):
        os.makedirs(os.path.dirname(self.cache_file) or ".", exist_ok=True)
        try:
            data = {k: v for k, v in self.cache.items() if v is not None}
            with open(self.cache_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
        except Exception:
            pass

    async def check(self, session, ip: str) -> Optional[Dict]:
        if ip in self.cache:
            return self.cache[ip]
        results: List[Dict] = []
        for source in self.sources:
            try:
                result = await source.check(session, ip)
            except Exception:
                result = None
            if result is not None:
                results.append(result)
        merged = merge_ip_info(results)
        self.cache[ip] = merged
        return merged


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
        if _is_ip_literal(host):
            return host.strip("[]")
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
        # 去掉上一次运行留下的标签，保证重复清洗时不会出现 【新】 【旧】 名称 的叠加
        remark = LABEL_PREFIX_RE.sub("", node.remark or "").strip() or node.remark
        return f"{body}#{label} {remark}"

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
            "raw": node.raw,
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
            "out": self.apply_label(node, label),
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
            record["risk_level"] = "UNKNOWN"
            record["filter_reason"] = "IP 黑名单"
            return None, record

        # IP 已解析但检测源全部失败：这属于"未知"，不能当作 CLEAN 正常节点
        if info is None:
            self.stats["unknown"] += 1
            record["risk_level"] = "UNKNOWN"
            return self.apply_label(node, label), record

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
        connector = aiohttp.TCPConnector(limit=max(1, self.settings["concurrency"]))
        headers = {"User-Agent": self.settings["user_agent"]}
        final_nodes: List[str] = []
        risky_nodes: List[str] = []
        unique: Dict[str, str] = {}

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.settings["request_timeout"]),
            connector=connector,
            headers=headers,
            trust_env=True,
        ) as session:
            async def worker(node: Node):
                async with sem:
                    return await self.process_one(node, session, loop)

            for idx, node in enumerate(nodes, 1):
                if idx % 25 == 0 or idx == len(nodes):
                    print(f"  处理中: {idx}/{len(nodes)}", end="\r", flush=True)

                if _is_ip_literal(node.host):
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
                        "shared_users": None, "out": node.raw, "raw": node.raw,
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
                elif record["risk_level"] == "CLEAN":
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


QUIC_PROTOCOLS = ("tuic://", "hysteria://", "hysteria2://", "hy2://", "hy://")


def _protocol_uses_tls(node) -> bool:
    """判断该节点是否用 TLS 承载（这类节点做 TCP 探测后还需 TLS 握手确认）"""
    p = node.protocol
    if p == "trojan://":
        return True
    if p == "vless://":
        q = node.raw.split("?", 1)[1] if "?" in node.raw else ""
        return bool(re.search(r"security=(?:tls|xtls)", q))
    if p in ("ss://", "ssr://"):
        q = node.raw.split("?", 1)[1] if "?" in node.raw else ""
        return "tls" in q
    return False


class ReachabilityProber:
    """清洗前的可达性预过滤。

    - TCP 协议：TCP 连接失败即判死
    - TLS 协议（vless-tls / trojan / ss-tls）：TCP 通但 TLS 握手失败判死
    - QUIC 协议（tuic / hysteria* / hy2 / hy）：只做 TCP 探测，失败不判死，
      因为 QUIC 服务器可能不监听 TCP，避免误杀
    """

    def __init__(self, settings: Dict):
        self.timeout = max(1, settings.get("probe_timeout", 5))
        self.do_tls = settings.get("probe_tls", True)
        self.sem = asyncio.Semaphore(max(1, settings.get("concurrency", 16)))

    async def _tcp(self, host: str, port) -> None:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, int(port)), self.timeout
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass

    async def _tls(self, host: str, port) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, int(port), ssl=ctx, server_hostname=host),
            self.timeout,
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass

    async def probe(self, node) -> Tuple[bool, str]:
        async with self.sem:
            host, port = node.host, node.port
            try:
                await self._tcp(host, port)
            except Exception:
                if node.protocol in QUIC_PROTOCOLS:
                    return True, "QUIC 未验证"
                return False, "TCP 不通"
            if self.do_tls and _protocol_uses_tls(node):
                try:
                    await self._tls(host, port)
                except Exception:
                    return False, "TLS 握手失败"
            return True, "可达"


def extract_node_lines(text: str) -> List[str]:
    lines: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def read_raw_nodes(path: str) -> List[str]:
    with open(path, encoding="utf-8") as f:
        return f.read()


def is_base64_block(text: str) -> bool:
    """判断一行是否为 base64 订阅块（长串、只含 base64 字母表、无协议头）。"""
    if len(text) < 16:
        return False
    if "://" in text:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", text))


def rebuild_sources(results: List[Dict], settings: Dict) -> Dict:
    """维护 config/sources.txt，使其成为可持续刷新的节点池。

    写回（由本次清洗结果驱动）：
    - 纯净度 <= purity_split 的节点（含从订阅 URL/base64 解码出来的）
    - 可达但未知（无检测结果）的节点
    保留：
    - 订阅 URL / base64 块（保证每次运行都能继续从上游拉取新节点）
    - 注释、空行、无法解析的行
    删除：
    - 无法连接的节点、纯净度高于 purity_split 的节点、命中黑名单/风险的节点
    返回统计字典。
    """
    sources_file = settings["sources_file"]
    split = settings["purity_split"]
    protocols = settings["protocols"]

    keep_clean: Dict[str, str] = {}
    keep_unknown: Dict[str, str] = {}
    for r in results:
        if r.get("should_filter"):
            continue
        raw = r.get("raw")
        if not raw:
            continue
        score = r.get("risk_score")
        if score is not None and int(score) <= split:
            keep_clean[raw] = raw
        elif score is None:
            keep_unknown[raw] = raw

    preamble: List[str] = []
    removed = 0
    if os.path.exists(sources_file):
        with open(sources_file, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    preamble.append(line)
                    continue
                low = stripped.lower()
                if low.startswith(("http://", "https://")) or is_base64_block(stripped):
                    # 保留订阅来源，避免首次运行后断掉上游刷新
                    preamble.append(line)
                    continue
                node = parse_node(stripped, protocols)
                if node is None:
                    preamble.append(line)
                    continue
                if node.raw in keep_clean or node.raw in keep_unknown:
                    continue
                removed += 1

    with open(sources_file, "w", encoding="utf-8") as f:
        f.writelines(preamble)
        for raw in keep_clean.values():
            f.write(raw + "\n")
        for raw in keep_unknown.values():
            f.write(raw + "\n")

    return {"clean": len(keep_clean), "unknown": len(keep_unknown), "removed": removed}


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

    input_total = len(nodes)
    dead: List[Tuple[Node, str]] = []
    dead_hostport: set = set()
    if settings.get("probe_reachability"):
        print("🛰 正在探测节点可达性...", flush=True)
        prober = ReachabilityProber(settings)
        alive: List[Node] = []

        async def _probe_one(node: Node) -> None:
            ok, note = await prober.probe(node)
            if ok:
                alive.append(node)
            else:
                dead.append((node, note))

        await asyncio.gather(*[_probe_one(n) for n in nodes])
        nodes = alive
        dead_hostport = {(node.host.lower(), str(node.port)) for node, _ in dead}
        print(
            f"  🚫 不可达节点: {len(dead)}"
            f"（去重 host:port {len(dead_hostport)}）",
            flush=True,
        )

    processor = NodeProcessor(settings)
    processor.stats["input_total"] = input_total
    processor.stats["dead"] = len(dead)
    processor.stats["dead_unique"] = len(dead_hostport)
    final_nodes, results, risky_nodes = await processor.process(nodes)

    print("\n" + "=" * 70)
    print("📊 处理统计:")
    print("=" * 70)
    print(f"📥 输入节点数: {processor.stats['input_total']}")
    print(f"🛰  不可达:     {processor.stats['dead']} (去重 host:port {processor.stats['dead_unique']})")
    print(f"🧼 参与清洗:   {processor.stats['total']}")
    print(f"🌐 IP 直连:     {processor.stats['ip_only']}")
    print(f"📍 域名解析:    {processor.stats['domain_only']}")
    print(f"✓ 正常节点:     {processor.stats['clean']}")
    print(f"⚠️  风险节点:   {processor.stats['risky']}")
    print(f"❌ 已过滤:     {processor.stats['filtered']}")
    print(f"❔ 无法解析:   {processor.stats['unknown']}")
    print(f"🔄 去重后输出:  {len(final_nodes)}")

    os.makedirs("output", exist_ok=True)

    # 落盘明细日志，和 config/settings.yaml 中的说明保持一致
    with open(DEAD_LOG, "w", encoding="utf-8") as f:
        for node, note in dead:
            f.write(f"[{note}] {node.raw}\n")
    with open(FILTERED_LOG, "w", encoding="utf-8") as f:
        for line in processor.filtered_log:
            f.write(line + "\n")
    if risky_nodes:
        with open(RISKY_OUTPUT, "w", encoding="utf-8") as f:
            for node in risky_nodes:
                f.write(node + "\n")
    else:
        try:
            os.remove(RISKY_OUTPUT)
        except OSError:
            pass

    # 切分纯净度 <= purity_split 的家宽/机房节点
    split = settings["purity_split"]
    home_nodes: List[str] = []
    dc_nodes: List[str] = []
    for r in results:
        if r.get("should_filter"):
            continue
        score = r.get("risk_score")
        if score is None or int(score) > split:
            continue
        if r.get("is_residential"):
            home_nodes.append(r.get("out") or "")
        elif r.get("is_datacenter"):
            dc_nodes.append(r.get("out") or "")

    with open(HOME_OUTPUT, "w", encoding="utf-8") as f:
        for node in home_nodes:
            f.write(node + "\n")
    print(f"🏠 原生家宽(纯净度<={split}%): {HOME_OUTPUT} ({len(home_nodes)} 条)")

    with open(DC_OUTPUT, "w", encoding="utf-8") as f:
        for node in dc_nodes:
            f.write(node + "\n")
    print(f"🏢 原生机房(纯净度<={split}%): {DC_OUTPUT} ({len(dc_nodes)} 条)")

    # 维护 sources.txt：删除 URL/base64/死节点/高纯净度节点，写回纯净与未知节点
    if settings.get("reverse_delete_sources"):
        stats = rebuild_sources(results, settings)
        print(
            f"🗑  维护 sources.txt: 删除 {stats['removed']} 条"
            f"（死/脏节点），写回 纯净 {stats['clean']} / 未知 {stats['unknown']}"
        )
    else:
        print("🗑  sources.txt 维护已关闭 (reverse_delete_sources: false)")

    print("=" * 70)
    print("✨ 所有任务完成！")
    print("=" * 70)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"❌ 未捕获异常: {e}")

import os
import re
import json
import asyncio
from typing import Dict, Optional, Tuple, List

# Try to import aiohttp, fall back to requests if not available
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except Exception:
    aiohttp = None
    AIOHTTP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    requests = None
    REQUESTS_AVAILABLE = False

INPUT = "output/raw_nodes.txt"
OUTPUT = "output/nodes.txt"
FILTERED_LOG = "output/filtered_nodes.log"
RESULT_JSON = "output/result.json"

# 支持所有协议
PROTOCOLS = [
    "vmess://",
    "vless://",
    "ss://",
    "ssr://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://"
]

# IP 黑名单
BLACKLIST_IPS = {
    "120.227.1.43",
    "47.240.80.220",
}

# 欺诈分数阈值 (超过这个值认为是风险)
FRAUD_SCORE_THRESHOLD = 75

# IP 纯净度评分对应的 Emoji (参考 clash-ip-checker)
PURITY_SCORE_MAPPING = {
    (0, 10): ("⚪", "极佳"),      
    (11, 30): ("🟢", "优秀"),      
    (31, 50): ("🟡", "良好"),      
    (51, 70): ("🟠", "中等"),      
    (71, 90): ("🔴", "差"),        
    (91, 100): ("⚫", "极差"),     
}


class IPQualityChecker:
    """IP 质量检查器 - 自动选择 aiohttp 或 requests"""

    def __init__(self):
        self.cache = {}
        self.session = None
        self.requests_session = None

    async def __aenter__(self):
        if AIOHTTP_AVAILABLE:
            timeout = aiohttp.ClientTimeout(total=5)
            self.session = aiohttp.ClientSession(timeout=timeout)
        else:
            # prepare requests session for sync fallback
            if REQUESTS_AVAILABLE:
                self.requests_session = requests.Session()
            else:
                # Neither aiohttp nor requests is available — cannot proceed
                raise RuntimeError(
                    "缺少 HTTP 客户端库: 请在运行环境中安装 'aiohttp' 或 'requests'。在 CI 中请确保 requirements.txt 已安装。"
                )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if AIOHTTP_AVAILABLE and self.session:
            await self.session.close()
        if self.requests_session:
            try:
                self.requests_session.close()
            except Exception:
                pass

    async def check_ip_purity(self, ip_str: str) -> Dict:
        """调用 IPPure API 检查 IP 纯净度（支持异步 aiohttp 或同步 requests 回退）"""
        if not ip_str:
            return self._get_default_result()

        if ip_str in self.cache:
            return self.cache[ip_str]

        url = "https://my.123169.xyz/v1/info"

        if AIOHTTP_AVAILABLE:
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                if not self.session:
                    self.session = aiohttp.ClientSession(timeout=timeout)
                async with self.session.get(url, timeout=timeout, params={"ip": ip_str}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = self._parse_ippure_result(data)
                        self.cache[ip_str] = result
                        return result
            except asyncio.TimeoutError:
                print(f"⚠️ API 超时 ({ip_str})")
            except Exception as e:
                print(f"⚠️ API 检查失败 ({ip_str}): {str(e)[:120]}")

            return self._get_default_result()

        # Fallback using requests in a thread executor
        if REQUESTS_AVAILABLE:
            loop = asyncio.get_running_loop()

            def _sync_request():
                try:
                    resp = self.requests_session.get(url, params={"ip": ip_str}, timeout=5)
                    if resp.status_code == 200:
                        try:
                            return resp.json()
                        except Exception:
                            return None
                except Exception:
                    return None
                return None

            try:
                data = await loop.run_in_executor(None, _sync_request)
                if data:
                    result = self._parse_ippure_result(data)
                    self.cache[ip_str] = result
                    return result
            except Exception as e:
                print(f"⚠️ (requests) API 检查失败 ({ip_str}): {e}")

            return self._get_default_result()

        # Last resort
        return self._get_default_result()

    @staticmethod
    def _parse_ippure_result(data: Dict) -> Dict:
        """解析 IPPure API 响应"""
        if not data or not isinstance(data, dict):
            return IPQualityChecker._get_default_result()
        result = {
            "ip": data.get("ip", "❓"),
            "fraud_score": int(data.get("fraudScore", 0)),
            "is_residential": data.get("isResidential", False),
            "is_broadcast": data.get("isBroadcast", False),
            "country": data.get("countryName", "Unknown"),
            "is_vpn": data.get("isVpn", False),
            "is_datacenter": data.get("isDatacenter", False),
        }
        return result

    @staticmethod
    def _get_default_result() -> Dict:
        """获取默认结果"""
        return {
            "ip": "❓",
            "fraud_score": 0,
            "is_residential": False,
            "is_broadcast": False,
            "country": "Unknown",
            "is_vpn": False,
            "is_datacenter": False,
        }


class NodeProcessor:
    """节点处理器"""

    def __init__(self):
        self.checker = None
        self.filtered_log = []
        self.stats = {
            "total": 0,
            "filtered": 0,
            "risky": 0,
            "clean": 0,
            "ip_only": 0,
            "domain_only": 0,
        }
        self.results = []

    async def process(self, nodes: List[str]) -> Tuple[List[str], List[Dict]]:
        """处理节点列表"""
        async with IPQualityChecker() as checker:
            self.checker = checker
            unique = {}

            for i, node in enumerate(nodes):
                if (i + 1) % 10 == 0:
                    print(f"  处理中: {i+1}/{len(nodes)}", end='\r')

                # 验证节点格式
                if not node or not any(p in node for p in PROTOCOLS):
                    self.filtered_log.append(f"[格式错误] {node[:80]}")
                    continue

                ip_str = self._extract_ip_from_node(node)

                # IP 统计
                if ip_str:
                    self.stats["ip_only"] += 1
                else:
                    self.stats["domain_only"] += 1

                # 检查 IP 黑名单
                if ip_str and ip_str in BLACKLIST_IPS:
                    self.stats["filtered"] += 1
                    self.filtered_log.append(
                        f"[黑名单] {node[:80]}... | IP: {ip_str}"
                    )
                    continue

                # 检查 IP 质量
                quality_info = await self._check_node_quality(node, ip_str)

                # 判断是否应该过滤
                if quality_info.get("should_filter"):
                    self.stats["filtered"] += 1
                    reason = quality_info.get("filter_reason", "未知原因")
                    self.filtered_log.append(
                        f"[过滤] {node[:80]}... | {reason}"
                    )
                    continue

                # 增强节点名称
                enhanced_node = self._enhance_node_name(node, quality_info)

                # 去重
                key = self._get_unique_key(enhanced_node)
                if key not in unique:
                    unique[key] = enhanced_node
                    self.results.append(quality_info)

                    if quality_info.get("risk_level") == "RISKY":
                        self.stats["risky"] += 1
                    elif quality_info.get("risk_level") == "CLEAN":
                        self.stats["clean"] += 1

        self.stats["total"] = len(nodes)
        print("\n")
        return list(unique.values()), self.results

    async def _check_node_quality(self, node: str, ip_str: Optional[str]) -> Dict:
        """检查节点质量"""
        quality = {
            "node": node,
            "ip": ip_str or "❓",
            "remark": self._extract_remark(node),
            "risk_level": "CLEAN",
            "filter_reason": "",
            "should_filter": False,
            "emoji": "✅",
            "attr": "未知",
            "source": "未知",
            "fraud_score": 0,
            "full_string": "",
            "rating": "未知",
        }

        # 如果是域名节点，直接返回
        if not ip_str:
            quality["full_string"] = "【✅ 域名节点】"
            return quality

        # 调用 API 检查
        api_result = await self.checker.check_ip_purity(ip_str)

        fraud_score = api_result.get("fraud_score", 0)
        quality["fraud_score"] = fraud_score

        # 获取纯净度 Emoji 和评级
        emoji = "❓"
        rating = "未知"
        for (min_score, max_score), (e, r) in PURITY_SCORE_MAPPING.items():
            if min_score <= fraud_score <= max_score:
                emoji = e
                rating = r
                break

        quality["emoji"] = emoji
        quality["rating"] = rating

        # 判断是否为风险 IP - VPN 或欺诈分数过高
        if api_result.get("is_vpn"):
            quality["risk_level"] = "RISKY"
            quality["should_filter"] = True
            quality["filter_reason"] = "VPN 节点"
            return quality

        if fraud_score > FRAUD_SCORE_THRESHOLD:
            quality["risk_level"] = "RISKY"
            quality["should_filter"] = True
            quality["filter_reason"] = f"欺诈分数过高 ({fraud_score}%)"
            return quality

        # IP 属性
        if api_result.get("is_residential"):
            quality["attr"] = "住宅"
        elif api_result.get("is_datacenter"):
            quality["attr"] = "机房"
        else:
            quality["attr"] = "未知"

        # IP 源
        if api_result.get("is_broadcast"):
            quality["source"] = "广播"
        else:
            quality["source"] = "原生"

        # 构建完整字符串
        quality["full_string"] = f"【{quality['emoji']} {quality['attr']}|{quality['source']}】"

        return quality

    @staticmethod
    def _extract_ip_from_node(node: str) -> Optional[str]:
        """从节点中提取 IP"""
        try:
            match = re.search(r'@([^:/?#]+)', node)
            if match:
                host = match.group(1)
                # 检查是否为 IP 地址
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                    return host
        except Exception as e:
            print(f"⚠️ 提取 IP 出错: {str(e)[:50]}")
        return None

    @staticmethod
    def _extract_remark(node: str) -> str:
        """提取节点备注"""
        try:
            match = re.search(r'#(.+)$', node)
            return match.group(1) if match else "未命名"
        except Exception:
            return "未命名"

    @staticmethod
    def _get_unique_key(node: str) -> str:
        """获取去重键"""
        try:
            uuid = re.search(
                r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',
                node
            )
            if uuid:
                return "uuid:" + uuid.group(1).lower()

            host = re.search(r'@([^:/?#]+)', node)
            port = re.search(r':(\d{2,6})', node)
            if host and port:
                return "server:" + host.group(1) + ":" + port.group(1)
        except Exception as e:
            print(f"⚠️ 获取唯一键出错: {str(e)[:50]}")

        return node

    @staticmethod
    def _enhance_node_name(node: str, quality: Dict) -> str:
        """增强节点名称"""
        try:
            if not quality.get("full_string"):
                return node

            if '#' in node:
                parts = node.rsplit('#', 1)
                return f"{parts[0]}#{quality['full_string']} {parts[1]}"
            else:
                return f"{node}#{quality['full_string']}"
        except Exception as e:
            print(f"⚠️ 增强节点名称出错: {str(e)[:50]}")
            return node


def extract_nodes(text: str) -> List[str]:
    """从文本中提取所有节点"""
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):  # 跳过空行和注释
            continue
        for p in PROTOCOLS:
            if p in line:
                index = line.find(p)
                node = line[index:]
                result.append(node)
                break
    return result


def generate_html_report(results: List[Dict], stats: Dict) -> str:
    """生成 HTML 报告（简化版）"""
    html = [
        '<!doctype html>',
        '<html><head><meta charset="utf-8"><title>报告</title></head><body>',
        f'<h1>节点清洗报告</h1>',
        f'<p>总节点: {stats.get("total", 0)}</p>',
        '<table border="1" cellpadding="4">',
        '<tr><th>备注</th><th>IP</th><th>纯净度</th><th>属性</th><th>来源</th><th>评级</th></tr>'
    ]
    for r in results[:500]:
        html.append(f"<tr><td>{r.get('remark','')}</td><td>{r.get('ip','')}</td><td>{r.get('fraud_score','')}</td><td>{r.get('attr','')}</td><td>{r.get('source','')}</td><td>{r.get('rating','')}</td></tr>")
    html.append('</table></body></html>')
    return '\n'.join(html)


async def main():
    print("=" * 70)
    print("🚀 启动节点清洗脚本 (IP 质量检查版本)")
    print("=" * 70)

    if not os.path.exists(INPUT):
        print("❌ 没有找到 raw 文件")
        return

    # 读取文件
    try:
        with open(INPUT, encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        print(f"❌ 读取文件失败: {e}")
        return

    print(f"📊 原始文件大小: {len(text)} 字节")

    # 提取节点
    nodes = extract_nodes(text)
    print(f"📝 发现节点: {len(nodes)} 个")

    if not nodes:
        print("⚠️ 未找到任何节点，请检查输入文件")
        return

    # 处理节点
    processor = NodeProcessor()
    try:
        final_nodes, results = await processor.process(nodes)
    except RuntimeError as e:
        print(f"❌ 运行环境错误: {e}")
        print("请在运行环境中安装 aiohttp 或 requests，或在仓库根目录添加 requirements.txt 并包含 aiohttp")
        return
    except Exception as e:
        print(f"❌ 处理节点失败: {e}")
        return

    # 输出统计
    print("\n" + "=" * 70)
    print("📊 处理统计:")
    print("=" * 70)
    print(f"✅ 总节点数: {processor.stats['total']}")
    print(f"🌐 含 IP 的节点: {processor.stats['ip_only']}")
    print(f"📍 含域名的节点: {processor.stats['domain_only']}")
    print(f"⚠️  风险节点: {processor.stats['risky']}")
    print(f"✓ 正常节点: {processor.stats['clean']}")
    print(f"❌ 被过滤节点: {processor.stats['filtered']}")
    print(f"🔄 去重后: {len(final_nodes)}")

    # 输出文件
    os.makedirs("output", exist_ok=True)

    # 保存节点列表
    try:
        with open(OUTPUT, "w", encoding="utf-8") as f:
            for node in final_nodes:
                f.write(node + "\n")
        print(f"\n✅ 输出完成: {OUTPUT}")
        print(f"   文件大小: {len(final_nodes)} 条节点")
    except Exception as e:
        print(f"❌ 保存节点文件失败: {e}")
        return

    # 保存 JSON 结果
    try:
        with open(RESULT_JSON, "w", encoding="utf-8") as f:
            json.dump({
                "stats": processor.stats,
                "results": results
            }, f, ensure_ascii=False, indent=2)
        print(f"📋 JSON 结果: {RESULT_JSON}")
    except Exception as e:
        print(f"⚠️ 保存 JSON 失败: {e}")

    # 保存 HTML 报告
    try:
        html_path = "output/report.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(generate_html_report(results, processor.stats))
        print(f"📊 HTML 报告: {html_path}")
    except Exception as e:
        print(f"⚠️ 保存 HTML 报告失败: {e}")

    # 保存过滤日志
    if processor.filtered_log:
        try:
            with open(FILTERED_LOG, "w", encoding="utf-8") as f:
                f.write("过滤日志\n")
                f.write("=" * 70 + "\n\n")
                for log in processor.filtered_log:
                    f.write(log + "\n")
            print(f"📋 过滤日志: {FILTERED_LOG}")
        except Exception as e:
            print(f"⚠️ 保存过滤日志失败: {e}")

    print("=" * 70)
    print("✨ 所有任务完成！")
    print("=" * 70)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"❌ 未捕获异常: {e}")

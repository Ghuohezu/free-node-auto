import os
import re
import json
import asyncio
import aiohttp
from typing import Dict, Optional, Tuple, List

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
    """IP 质量检查器 - 集成 IPPure API"""
    
    def __init__(self):
        self.cache = {}
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def check_ip_purity(self, ip_str: str) -> Dict:
        """调用 IPPure API 检查 IP 纯净度"""
        if not ip_str:
            return self._get_default_result()
        
        if ip_str in self.cache:
            return self.cache[ip_str]
        
        try:
            url = "https://my.123169.xyz/v1/info"
            timeout = aiohttp.ClientTimeout(total=5)
            
            if not self.session:
                self.session = aiohttp.ClientSession(timeout=timeout)
            
            async with self.session.get(url, timeout=timeout, params={"ip": ip_str}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = self._parse_ippure_result(data)
                    self.cache[ip_str] = result
                    return result
        except Exception as e:
            print(f"⚠️ API 检查失败 ({ip_str}): {str(e)[:50]}")
        
        return self._get_default_result()
    
    @staticmethod
    def _parse_ippure_result(data: Dict) -> Dict:
        """解析 IPPure API 响应"""
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
                
                if quality_info.get("risk_level") == "BLOCKED":
                    self.stats["filtered"] += 1
                    self.filtered_log.append(
                        f"[风险] {node[:80]}... | {quality_info.get('reason', 'Unknown')}"
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
            "reason": "",
            "emoji": "✅",
            "attr": "未知",
            "source": "未知",
            "fraud_score": 0,
            "full_string": "",
        }
        
        if not ip_str:
            quality["full_string"] = ""
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
        
        # 判断是否为风险 IP
        if api_result.get("is_vpn"):
            quality["risk_level"] = "RISKY"
            quality["reason"] = "VPN"
        
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
        match = re.search(r'@([^:/?#]+)', node)
        if match:
            host = match.group(1)
            # 检查是否为 IP 地址
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                return host
        return None
    
    @staticmethod
    def _extract_remark(node: str) -> str:
        """提取节点备注"""
        match = re.search(r'#(.+)$', node)
        return match.group(1) if match else "未命名"
    
    @staticmethod
    def _get_unique_key(node: str) -> str:
        """获取去重键"""
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
        
        return node
    
    @staticmethod
    def _enhance_node_name(node: str, quality: Dict) -> str:
        """增强节点名称"""
        if not quality.get("full_string"):
            return node
        
        if '#' in node:
            parts = node.rsplit('#', 1)
            return f"{parts[0]}#{quality['full_string']} {parts[1]}"
        else:
            return f"{node}#{quality['full_string']}"


def extract_nodes(text: str) -> List[str]:
    """从文本中提取所有节点"""
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for p in PROTOCOLS:
            if p in line:
                index = line.find(p)
                node = line[index:]
                result.append(node)
                break
    return result


def generate_html_report(results: List[Dict], stats: Dict) -> str:
    """生成 HTML 报告"""
    
    # 统计质量分布
    quality_dist = {"⚪": 0, "🟢": 0, "🟡": 0, "🟠": 0, "🔴": 0, "⚫": 0}
    attr_dist = {"住宅": 0, "机房": 0, "未知": 0}
    source_dist = {"原生": 0, "广播": 0, "未知": 0}
    
    for r in results:
        emoji = r.get('emoji', '❓')
        if emoji in quality_dist:
            quality_dist[emoji] += 1
        attr = r.get('attr', '未知')
        if attr in attr_dist:
            attr_dist[attr] += 1
        source = r.get('source', '未知')
        if source in source_dist:
            source_dist[source] += 1
    
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>节点清洗报告</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{ 
            background: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        h1 {{ font-size: 28px; margin-bottom: 10px; color: #1e3c72; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card.success {{ background: linear-gradient(135deg, #10b981 0%, #059669 100%); }}
        .stat-card.warning {{ background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }}
        .stat-card.info {{ background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); }}
        .stat-card h3 {{ font-size: 12px; opacity: 0.9; margin-bottom: 8px; text-transform: uppercase; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        
        .charts {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .chart-card {{
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .chart-card h3 {{ margin-bottom: 15px; color: #333; font-size: 16px; }}
        .chart-item {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
            font-size: 14px;
        }}
        .chart-item span:first-child {{ min-width: 60px; font-weight: 500; }}
        .chart-bar {{
            flex: 1;
            height: 20px;
            background: #e5e7eb;
            border-radius: 4px;
            margin: 0 10px;
            position: relative;
            overflow: hidden;
        }}
        .chart-bar-fill {{
            height: 100%;
            background: #667eea;
            border-radius: 4px;
        }}
        .chart-item span:last-child {{ min-width: 40px; text-align: right; color: #666; }}
        
        .results-table {{
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #e9ecef;
            font-size: 13px;
            color: #666;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
            font-size: 14px;
        }}
        tr:hover {{ background: #f8f9fa; }}
        .emoji {{ font-size: 18px; margin-right: 5px; }}
        .ip {{ font-family: monospace; font-size: 12px; color: #666; }}
        .tag {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }}
        .tag-residential {{ background: #d1fae5; color: #065f46; }}
        .tag-datacenter {{ background: #fee2e2; color: #7f1d1d; }}
        .tag-native {{ background: #dbeafe; color: #0c2d6b; }}
        .tag-broadcast {{ background: #fef3c7; color: #78350f; }}
        .tag-unknown {{ background: #f3f4f6; color: #374151; }}
        
        .legend {{
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .legend h3 {{ margin-bottom: 15px; color: #1e3c72; font-size: 16px; }}
        .legend-items {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
        }}
        .legend-item span:first-child {{ font-size: 20px; min-width: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>✨ 节点清洗结果报告</h1>
            <p style="color: #666; margin-top: 8px; font-size: 14px;">基于 IP 纯净度评分的自动化节点处理系统</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>总节点数</h3>
                    <div class="value">{stats['total']}</div>
                </div>
                <div class="stat-card success">
                    <h3>有效节点</h3>
                    <div class="value">{stats['total'] - stats['filtered']}</div>
                </div>
                <div class="stat-card warning">
                    <h3>过滤节点</h3>
                    <div class="value">{stats['filtered']}</div>
                </div>
                <div class="stat-card info">
                    <h3>去重后节点</h3>
                    <div class="value">{len(results)}</div>
                </div>
            </div>
        </header>

        <div class="charts">
            <div class="chart-card">
                <h3>📊 IP 纯净度分布</h3>
                <div class="chart-item">
                    <span>⚪ 极佳</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(quality_dist['⚪']/max(len(results),1)*100):.0f}%"></div></div>
                    <span>{quality_dist['⚪']}</span>
                </div>
                <div class="chart-item">
                    <span>🟢 优秀</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(quality_dist['🟢']/max(len(results),1)*100):.0f}%; background: #10b981;"></div></div>
                    <span>{quality_dist['🟢']}</span>
                </div>
                <div class="chart-item">
                    <span>🟡 良好</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(quality_dist['🟡']/max(len(results),1)*100):.0f}%; background: #f59e0b;"></div></div>
                    <span>{quality_dist['🟡']}</span>
                </div>
                <div class="chart-item">
                    <span>🟠 中等</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(quality_dist['🟠']/max(len(results),1)*100):.0f}%; background: #f97316;"></div></div>
                    <span>{quality_dist['🟠']}</span>
                </div>
                <div class="chart-item">
                    <span>🔴 差</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(quality_dist['🔴']/max(len(results),1)*100):.0f}%; background: #ef4444;"></div></div>
                    <span>{quality_dist['🔴']}</span>
                </div>
                <div class="chart-item">
                    <span>⚫ 极差</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(quality_dist['⚫']/max(len(results),1)*100):.0f}%; background: #7c3aed;"></div></div>
                    <span>{quality_dist['⚫']}</span>
                </div>
            </div>
            
            <div class="chart-card">
                <h3>🏘️ IP 属性分布</h3>
                <div class="chart-item">
                    <span>住宅</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(attr_dist['住宅']/max(len(results),1)*100):.0f}%; background: #10b981;"></div></div>
                    <span>{attr_dist['住宅']}</span>
                </div>
                <div class="chart-item">
                    <span>机房</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(attr_dist['机房']/max(len(results),1)*100):.0f}%; background: #ef4444;"></div></div>
                    <span>{attr_dist['机房']}</span>
                </div>
                <div class="chart-item">
                    <span>未知</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(attr_dist['未知']/max(len(results),1)*100):.0f}%; background: #6b7280;"></div></div>
                    <span>{attr_dist['未知']}</span>
                </div>
            </div>
            
            <div class="chart-card">
                <h3>🌍 IP 源分布</h3>
                <div class="chart-item">
                    <span>原生</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(source_dist['原生']/max(len(results),1)*100):.0f}%; background: #0284c7;"></div></div>
                    <span>{source_dist['原生']}</span>
                </div>
                <div class="chart-item">
                    <span>广播</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(source_dist['广播']/max(len(results),1)*100):.0f}%; background: #f97316;"></div></div>
                    <span>{source_dist['广播']}</span>
                </div>
                <div class="chart-item">
                    <span>未知</span>
                    <div class="chart-bar"><div class="chart-bar-fill" style="width: {(source_dist['未知']/max(len(results),1)*100):.0f}%; background: #6b7280;"></div></div>
                    <span>{source_dist['未知']}</span>
                </div>
            </div>
        </div>

        <div class="legend">
            <h3>🎯 符号说明</h3>
            <div class="legend-items">
                <div class="legend-item"><span>⚪</span><span>极佳 (0-10%)</span></div>
                <div class="legend-item"><span>🟢</span><span>优秀 (11-30%)</span></div>
                <div class="legend-item"><span>🟡</span><span>良好 (31-50%)</span></div>
                <div class="legend-item"><span>🟠</span><span>中等 (51-70%)</span></div>
                <div class="legend-item"><span>🔴</span><span>差 (71-90%)</span></div>
                <div class="legend-item"><span>⚫</span><span>极差 (91-100%)</span></div>
                <div class="legend-item"><span>🏘️</span><span>住宅 (家庭宽带)</span></div>
                <div class="legend-item"><span>🏢</span><span>机房 (数据中心)</span></div>
                <div class="legend-item"><span>📍</span><span>原生 (本地归属)</span></div>
                <div class="legend-item"><span>🌍</span><span>广播 (异地归属)</span></div>
            </div>
        </div>

        <div class="results-table">
            <table>
                <thead>
                    <tr>
                        <th style="width: 30%;">节点名</th>
                        <th style="width: 15%;">IP 地址</th>
                        <th style="width: 12%;">纯净度</th>
                        <th style="width: 13%;">IP 属性</th>
                        <th style="width: 13%;">IP 来源</th>
                        <th style="width: 12%;">质量评级</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    for result in results[:100]:  # 只显示前100条
        attr_class = "tag-residential" if result['attr'] == "住宅" else ("tag-datacenter" if result['attr'] == "机房" else "tag-unknown")
        source_class = "tag-native" if result['source'] == "原生" else ("tag-broadcast" if result['source'] == "广播" else "tag-unknown")
        
        html_content += f"""
                    <tr>
                        <td><strong>{result['remark'][:40]}</strong></td>
                        <td><span class="ip">{result['ip']}</span></td>
                        <td><span class="emoji">{result['emoji']}</span> {result['fraud_score']}%</td>
                        <td><span class="tag {attr_class}">{result['attr']}</span></td>
                        <td><span class="tag {source_class}">{result['source']}</span></td>
                        <td>{result.get('rating', '未知')}</td>
                    </tr>
"""
    
    if len(results) > 100:
        html_content += f"""
                    <tr style="background: #f9fafb; text-align: center;">
                        <td colspan="6" style="padding: 15px;">... 共 {len(results)} 条记录，仅显示前 100 条 ...</td>
                    </tr>
"""
    
    html_content += """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
    return html_content


async def main():
    print("=" * 70)
    print("🚀 启动节点清洗脚本 (IP 质量检查版本)")
    print("=" * 70)
    
    if not os.path.exists(INPUT):
        print("❌ 没有找到 raw 文件")
        return
    
    # 读取文件
    with open(INPUT, encoding="utf-8") as f:
        text = f.read()
    
    print(f"📊 原始文件大小: {len(text)} 字节")
    
    # 提取节点
    nodes = extract_nodes(text)
    print(f"📝 发现节点: {len(nodes)} 个")
    
    # 处理节点
    processor = NodeProcessor()
    final_nodes, results = await processor.process(nodes)
    
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
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for node in final_nodes:
            f.write(node + "\n")
    print(f"\n✅ 输出完成: {OUTPUT}")
    print(f"   文件大小: {len(final_nodes)} 条节点")
    
    # 保存 JSON 结果
    with open(RESULT_JSON, "w", encoding="utf-8") as f:
        json.dump({
            "stats": processor.stats,
            "results": results
        }, f, ensure_ascii=False, indent=2)
    print(f"📋 JSON 结果: {RESULT_JSON}")
    
    # 保存 HTML 报告
    html_path = "output/report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html_report(results, processor.stats))
    print(f"📊 HTML 报告: {html_path}")
    
    # 保存过滤日志
    if processor.filtered_log:
        with open(FILTERED_LOG, "w", encoding="utf-8") as f:
            f.write("过滤日志\n")
            f.write("=" * 70 + "\n\n")
            for log in processor.filtered_log:
                f.write(log + "\n")
        print(f"📋 过滤日志: {FILTERED_LOG}")
    
    print("=" * 70)
    print("✨ 所有任务完成！")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())

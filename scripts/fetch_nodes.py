import base64
import os
import re
from urllib.parse import unquote

import requests

SOURCES = "config/sources.txt"
OUTPUT = "output/raw_nodes.txt"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) node-fetcher/2.0",
    "Accept": "*/*",
}

# 与 clean_nodes.py 保持一致的协议列表
PROTOCOLS = [
    "vmess://",
    "vless://",
    "ss://",
    "ssr://",
    "trojan://",
    "anytls://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "hy://",
    "tuic://",
]

B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def decode_base64_block(text: str):
    results = []
    clean = text.replace("\n", "").replace("\r", "")
    if len(clean) >= 16:
        try:
            data = base64.b64decode(clean + "=" * (-len(clean) % 4),
                                    validate=False).decode("utf-8", errors="ignore")
            if "://" in data:
                results.append(data)
        except Exception:
            pass

    for match in B64_RUN.findall(text):
        try:
            data = base64.b64decode(match + "=" * (-len(match) % 4),
                                    validate=False).decode("utf-8", errors="ignore")
            if "://" in data:
                results.append(data)
        except Exception:
            continue
    return results


def is_direct_node_line(line: str) -> bool:
    low = line.lower().strip()
    for p in PROTOCOLS:
        if low.startswith(p):
            return True
    if "://" in low and not low.startswith(("http://", "https://", "ftp://", "ftps://")):
        return True
    return False


def read_sources(path: str):
    if not os.path.exists(path):
        return []
    urls = []
    seen = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line in seen:
                continue
            seen.add(line)
            urls.append(line)
    return urls


def ingest_text(chunks, text):
    chunks.append(text)
    chunks.extend(decode_base64_block(text))


def main():
    os.makedirs("output", exist_ok=True)

    sources = read_sources(SOURCES)
    print(f"订阅/来源数量: {len(sources)}")

    chunks = []
    for src in sources:
        try:
            if is_direct_node_line(src):
                chunks.append(src)
                continue

            if os.path.exists(src) and os.path.isfile(src):
                print(f"读取本地文件: {src}")
                with open(src, encoding="utf-8") as fh:
                    ingest_text(chunks, fh.read())
                continue

            if not src.lower().startswith(("http://", "https://")):
                # 非 HTTP 来源：伪协议订阅串或 base64 编码的订阅内容，按节点文本处理
                ingest_text(chunks, src)
                continue

            print(f"抓取 URL: {src}")
            resp = requests.get(
                src, headers=HEADERS, timeout=30,
                allow_redirects=True, stream=True
            )
            text = unquote(resp.text)
            print(f"  状态: {resp.status_code} 长度: {len(text)}")
            ingest_text(chunks, text)

        except Exception as e:
            print(f"  失败: {e}")

    nodes = []
    seen = set()
    for chunk in chunks:
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            if line in seen:
                continue
            seen.add(line)
            nodes.append(line)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for node in nodes:
            f.write(node + "\n")

    print(f"\n生成: {OUTPUT} ({len(nodes)} 行，去重后)")


if __name__ == "__main__":
    main()

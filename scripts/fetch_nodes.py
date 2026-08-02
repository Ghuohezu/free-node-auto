import requests
import os
import base64

SOURCES = "config/sources.txt"
OUTPUT = "output/raw_nodes.txt"

headers = {
    "User-Agent": "Mozilla/5.0"
}

# 与 clean_nodes.py 保持一致的协议列表
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


def try_decode_base64(text):
    result = []
    try:
        clean = text.replace("\n", "").replace("\r", "")
        data = base64.b64decode(clean + "===").decode("utf-8", errors="ignore")
        if "://" in data:
            result.append(data)
    except:
        pass
    return result


def is_direct_node_line(line: str) -> bool:
    """
    判断配置行是否为直接的节点链接（例如 vmess://xxx）或其它非 http(s) 协议的链接。
    """
    if not line:
        return False
    low = line.lower().strip()
    for p in PROTOCOLS:
        if low.startswith(p):
            return True
    # 若包含 :// 但不是 http(s) 开头，则认为是直接节点或非订阅链接（比如 vmess://、ss:// 等）
    if "://" in low and not low.startswith(("http://", "https://", "ftp://", "ftps://")):
        return True
    return False


def main():
    os.makedirs("output", exist_ok=True)

    if not os.path.exists(SOURCES):
        print("没有 sources.txt")
        return

    urls = []
    with open(SOURCES, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)

    print("订阅/来源数量:", len(urls))

    nodes = []

    for src in urls:
        try:
            # 如果配置里直接写了节点（vmess://... 或其他协议），直接当作节点加入
            if is_direct_node_line(src):
                print("直接节点行, 添加:", src if len(src) < 120 else src[:120] + "...")
                nodes.append(src)
                continue

            # 如果配置项是一个本地文件路径，读取文件内容
            if os.path.exists(src) and os.path.isfile(src):
                print("读取本地文件:", src)
                with open(src, encoding="utf-8") as fh:
                    text = fh.read()
                nodes.append(text)
                nodes.extend(try_decode_base64(text))
                continue

            # 否则按 URL 抓取（原有行为）
            print("抓取 URL:", src)
            r = requests.get(src, headers=headers, timeout=30)
            print("状态:", r.status_code, "长度:", len(r.text))
            text = r.text
            nodes.append(text)
            nodes.extend(try_decode_base64(text))

        except Exception as e:
            print("失败:", e)

    # 将所有原始抓取内容（包含直接节点行、订阅页面、解码出的节点）写到 output/raw_nodes.txt
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for n in nodes:
            # 确保每行末尾换行
            f.write(n + "\n")

    print("生成:", OUTPUT)


if __name__ == "__main__":
    main()

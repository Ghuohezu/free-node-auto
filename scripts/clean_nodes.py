
import requests
import os
import base64
import yaml
import re


SOURCE_FILE = "config/sources.txt"
OUTPUT_FILE = "output/nodes.txt"


def download(url):

    print("正在抓取:", url)

    try:
        r = requests.get(
            url,
            timeout=20,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        r.raise_for_status()

        return r.text

    except Exception as e:
        print("抓取失败:", e)
        return ""


def decode_base64(text):

    try:

        clean = re.sub(
            r"\s+",
            "",
            text
        )

        decoded = base64.b64decode(
            clean + "=="
        ).decode(
            "utf-8",
            errors="ignore"
        )

        return decoded

    except:

        return text



def extract_nodes(text):

    nodes=[]


    # 直接节点

    for line in text.splitlines():

        line=line.strip()


        if (
            line.startswith("vmess://")
            or line.startswith("vless://")
            or line.startswith("ss://")
            or line.startswith("trojan://")
            or line.startswith("hysteria://")
        ):

            nodes.append(line)



    # Base64订阅

    if len(nodes)==0:

        decoded=decode_base64(text)

        for line in decoded.splitlines():

            line=line.strip()

            if (
                line.startswith("vmess://")
                or line.startswith("vless://")
                or line.startswith("ss://")
                or line.startswith("trojan://")
                or line.startswith("hysteria://")
            ):

                nodes.append(line)



    return nodes




def main():


    os.makedirs(
        "output",
        exist_ok=True
    )


    all_nodes=set()



    with open(
        SOURCE_FILE,
        encoding="utf-8"
    ) as f:

        urls=[
            x.strip()
            for x in f.readlines()
            if x.strip()
        ]



    for url in urls:

        data=download(url)

        nodes=extract_nodes(data)

        print(
            "发现节点:",
            len(nodes)
        )


        for n in nodes:

            all_nodes.add(n)



    print(
        "去重后:",
        len(all_nodes)
    )



    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        for node in sorted(all_nodes):

            f.write(
                node+"\n"
            )



    print(
        "生成完成:",
        OUTPUT_FILE
    )



if __name__=="__main__":

    main()

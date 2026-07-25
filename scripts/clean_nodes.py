import requests
import base64
import re
import os
import yaml
from urllib.parse import urlparse


SOURCE_FILE="config/sources.txt"
OUTPUT_FILE="output/nodes.txt"


nodes=[]


def download(url):

    try:
        r=requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent":"Mozilla/5.0"
            }
        )

        r.raise_for_status()

        return r.text

    except Exception as e:
        print("下载失败:",url,e)
        return ""


def decode_base64(text):

    try:
        raw=base64.b64decode(
            text + "="*((4-len(text)%4)%4)
        )

        return raw.decode(
            "utf-8",
            errors="ignore"
        )

    except:
        return text



def extract(text):

    result=[]


    # vless vmess ss trojan
    urls=re.findall(
        r'(?:vmess|vless|ss|trojan)://[^\s]+',
        text
    )


    result.extend(urls)


    # base64再次解析

    if len(result)==0:

        decoded=decode_base64(text)

        urls=re.findall(
            r'(?:vmess|vless|ss|trojan)://[^\s]+',
            decoded
        )

        result.extend(urls)


    return result



def node_key(node):

    """
    核心去重
    """

    # vless

    if node.startswith("vless://"):

        try:

            body=node[8:]

            uuid=body.split("@")[0]

            server=body.split("@")[1].split(":")[0]

            port=body.split("@")[1].split(":")[1].split("?")[0]


            return (
                "vless",
                server,
                port,
                uuid
            )

        except:
            pass


    # trojan

    if node.startswith("trojan://"):

        try:

            body=node[9:]

            pwd=body.split("@")[0]

            server=body.split("@")[1].split(":")[0]

            port=body.split("@")[1].split(":")[1].split("?")[0]


            return (
                "trojan",
                server,
                port,
                pwd
            )

        except:
            pass



    # 普通fallback

    return node



def main():

    with open(
        SOURCE_FILE,
        encoding="utf8"
    ) as f:

        urls=[
            x.strip()
            for x in f
            if x.strip()
        ]


    for url in urls:

        print(
            "抓取:",
            url
        )

        text=download(url)

        nodes.extend(
            extract(text)
        )


    print(
        "原始节点:",
        len(nodes)
    )


    clean=[]

    seen=set()


    for n in nodes:

        key=node_key(n)

        if key not in seen:

            seen.add(key)

            clean.append(n)



    print(
        "去重后:",
        len(clean)
    )


    os.makedirs(
        "output",
        exist_ok=True
    )


    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf8"
    ) as f:

        for n in clean:

            f.write(n+"\n")



if __name__=="__main__":
    main()

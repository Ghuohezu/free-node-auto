import requests
import os
import base64
import json
import urllib.parse
import re


SOURCE_FILE = "config/sources.txt"
OUTPUT_FILE = "output/nodes.txt"



def download(url):

    try:

        r=requests.get(
            url,
            timeout=20,
            headers={
                "User-Agent":"Mozilla/5.0"
            }
        )


        if r.status_code==200:

            text=r.text.strip()

            return parse_sub(text)


    except Exception as e:

        print(
            "下载失败:",
            url,
            e
        )


    return []




def parse_sub(text):

    nodes=[]


    # 已经是节点格式

    if (
        "://" in text
    ):

        nodes.extend(
            text.splitlines()
        )

        return nodes



    # Base64订阅

    try:

        decode=base64.b64decode(
            text+
            "="*((4-len(text)%4)%4)
        ).decode(
            "utf-8",
            errors="ignore"
        )


        nodes.extend(
            decode.splitlines()
        )


    except:

        pass


    return nodes




def node_key(node):


    try:

        url=urllib.parse.urlparse(node)


        scheme=url.scheme.lower()



        # VLESS

        if scheme=="vless":

            uuid=node.split("://")[1].split("@")[0]

            server=url.hostname

            port=url.port


            return (
                "vless",
                server,
                port,
                uuid
            )



        # VMESS

        if scheme=="vmess":

            return node



        # TROJAN

        if scheme=="trojan":

            password=node.split("://")[1].split("@")[0]

            return (
                "trojan",
                url.hostname,
                url.port,
                password
            )



        # SS

        if scheme=="ss":

            return (
                "ss",
                url.hostname,
                url.port,
                node.split("@")[0]
            )



    except:

        pass



    # 普通文本

    return node




def main():


    all_nodes=[]


    with open(
        SOURCE_FILE,
        encoding="utf-8"
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


        nodes=download(url)


        print(
            "获得:",
            len(nodes)
        )


        all_nodes.extend(nodes)



    print(
        "总节点:",
        len(all_nodes)
    )



    result={}



    for n in all_nodes:


        n=n.strip()


        if not n:
            continue


        key=node_key(n)


        if key not in result:

            result[key]=n




    clean=list(
        result.values()
    )



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
        encoding="utf-8"
    ) as f:


        f.write(
            "\n".join(clean)
        )



if __name__=="__main__":

    main()

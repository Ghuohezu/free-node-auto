import os
import re
import base64


INPUT = "output/raw_nodes.txt"

OUTPUT = "output/nodes.txt"



# 支持的节点协议

PROTOCOLS = [
    "vmess://",
    "vless://",
    "ss://",
    "trojan://",
    "hysteria://",
    "hy2://",
    "tuic://"
]



def read_file():

    if not os.path.exists(INPUT):

        print("没有找到:", INPUT)

        return ""


    with open(
        INPUT,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        return f.read()



def decode_base64(text):

    result=[]


    try:

        clean=text.replace("\n","").replace("\r","")


        data=base64.b64decode(
            clean+"==="
        ).decode(
            "utf-8",
            errors="ignore"
        )


        if "://" in data:

            result.append(data)


    except:

        pass


    return result




def extract_nodes(text):

    nodes=[]


    # 原始URI

    for line in text.splitlines():

        line=line.strip()


        for p in PROTOCOLS:

            if line.startswith(p):

                nodes.append(line)



    # Base64订阅

    nodes.extend(
        decode_base64(text)
    )


    return nodes




def node_key(node):

    """
    节点唯一识别

    优先:
    UUID

    其次:
    server:port

    """

    # UUID

    uuid=re.findall(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}",
        node
    )


    if uuid:

        return "uuid:"+uuid[0].lower()



    # server port

    server=re.search(
        r"@([^:/?#]+):(\d+)",
        node
    )


    if server:

        return (
            "server:"
            +
            server.group(1)
            +
            ":"
            +
            server.group(2)
        )



    # 普通SS格式

    server=re.search(
        r"([^:/]+):(\d+)",
        node
    )


    if server:

        return (
            "server:"
            +
            server.group(1)
            +
            ":"
            +
            server.group(2)
        )



    return node[:80]




def clean_nodes(nodes):

    result=[]

    seen=set()



    for node in nodes:


        key=node_key(node)


        if key in seen:

            continue



        seen.add(key)


        result.append(node)



    return result




def save(nodes):


    os.makedirs(
        "output",
        exist_ok=True
    )


    # 强制清空旧文件

    if os.path.exists(OUTPUT):

        open(
            OUTPUT,
            "w",
            encoding="utf-8"
        ).close()



    # 全新写入

    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:


        for n in nodes:

            f.write(
                n.strip()
                +
                "\n"
            )




def main():


    print("读取节点...")


    raw=read_file()


    print(
        "原始长度:",
        len(raw)
    )



    nodes=extract_nodes(raw)


    print(
        "发现节点:",
        len(nodes)
    )



    clean=clean_nodes(nodes)


    print(
        "去重后:",
        len(clean)
    )



    save(clean)


    print(
        "输出完成:",
        OUTPUT,
        "数量:",
        len(clean)
    )




if __name__=="__main__":

    main()

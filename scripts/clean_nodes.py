import os
import re
import base64
import yaml


INPUT_FILES = [
    "sources.txt",
    "nodes.txt",
    "output/raw_nodes.txt",
    "output/nodes_raw.txt"
]

OUTPUT_FILE = "output/nodes.txt"


def read_files():

    data = ""

    for file in INPUT_FILES:

        if os.path.exists(file):

            try:
                with open(file,"r",encoding="utf-8") as f:
                    data += "\n" + f.read()

            except:
                pass

    return data



def decode_base64(text):

    result=[]

    for line in text.splitlines():

        line=line.strip()

        if len(line)<20:
            continue


        try:

            if re.match(r'^[A-Za-z0-9+/=]+$',line):

                decode=base64.b64decode(
                    line+"==="

                ).decode(
                    "utf-8",
                    errors="ignore"
                )

                if "://" in decode:

                    result.append(decode)


        except:

            pass


    return result



def extract_nodes(text):

    nodes=[]


    # 原始 URI

    for line in text.splitlines():

        line=line.strip()

        if "://" in line:

            nodes.append(line)



    # base64

    nodes.extend(
        decode_base64(text)
    )


    return nodes



def node_key(node):

    """
    节点唯一识别
    """

    server=""
    port=""
    uuid=""
    password=""


    # server

    m=re.search(
        r'@([^:/?#]+)',
        node
    )

    if m:
        server=m.group(1)


    # port

    m=re.search(
        r'@[^:]+:(\d+)',
        node
    )

    if m:
        port=m.group(1)


    # uuid

    m=re.search(
        r'[0-9a-fA-F-]{32,}',
        node
    )

    if m:
        uuid=m.group(0)


    # password

    if "ss://" in node:

        try:

            password=node.split("@")[0]

            password=password[-30:]

        except:

            pass


    return (
        server,
        port,
        uuid,
        password
    )



def clean(nodes):


    result=[]

    seen=set()


    for n in nodes:


        key=node_key(n)


        if key in seen:

            continue


        seen.add(key)

        result.append(n)


    return result




def save(nodes):


    os.makedirs(
        "output",
        exist_ok=True
    )


    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:


        for n in nodes:

            f.write(n+"\n")




if __name__=="__main__":


    print("读取节点...")


    text=read_files()


    print(
        "原始长度:",
        len(text)
    )


    nodes=extract_nodes(text)


    print(
        "发现节点:",
        len(nodes)
    )


    nodes=clean(nodes)


    print(
        "去重后:",
        len(nodes)
    )


    save(nodes)


    print(
        "输出完成:",
        OUTPUT_FILE
    )

import os
import re



INPUT="output/raw_nodes.txt"

OUTPUT="output/nodes.txt"



# 支持所有协议

PROTOCOLS=[
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



def extract_nodes(text):

    result=[]


    for line in text.splitlines():


        line=line.strip()


        if not line:

            continue



        for p in PROTOCOLS:


            if p in line:


                index=line.find(p)


                node=line[index:]


                result.append(node)


                break



    return result



def get_unique_key(node):


    """
    去重核心

    优先:
    uuid

    其次:
    server+port

    """


    uuid=re.search(
        r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',
        node
    )


    if uuid:


        return "uuid:"+uuid.group(1).lower()



    host=re.search(
        r'@([^:/?#]+)',
        node
    )


    port=re.search(
        r':(\d{2,6})',
        node
    )


    if host and port:


        return (
            "server:"
            +host.group(1)
            +":"
            +port.group(1)
        )


    return node



def main():


    print(
        "读取节点..."
    )



    if not os.path.exists(INPUT):

        print(
            "没有raw文件"
        )

        return



    with open(
        INPUT,
        encoding="utf-8"
    ) as f:

        text=f.read()



    print(
        "原始长度:",
        len(text)
    )



    nodes=extract_nodes(text)



    print(
        "发现节点:",
        len(nodes)
    )



    unique={}



    for node in nodes:


        key=get_unique_key(node)


        if key not in unique:


            unique[key]=node



    final=list(
        unique.values()
    )



    print(
        "去重后:",
        len(final)
    )



    os.makedirs(
        "output",
        exist_ok=True
    )


    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:


        for node in final:


            f.write(
                node+"\n"
            )



    print(
        "输出完成:",
        OUTPUT
    )


    print(
        "最终文件数量:",
        len(final)
    )



if __name__=="__main__":

    main()

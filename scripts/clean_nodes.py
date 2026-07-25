import os
import re


INPUT = "output/raw_nodes.txt"
OUTPUT = "output/nodes.txt"


def node_key(node):

    node=node.strip()


    # VLESS
    if node.startswith("vless://"):

        m=re.search(
            r'vless://([^@]+)@([^:]+):(\d+)',
            node
        )

        if m:

            uuid,server,port=m.groups()

            return (
                "vless|"
                +server+
                "|"+
                port+
                "|"+
                uuid
            )



    # Trojan

    if node.startswith("trojan://"):

        m=re.search(
            r'trojan://([^@]+)@([^:]+):(\d+)',
            node
        )

        if m:

            password,server,port=m.groups()

            return (
                "trojan|"
                +server+
                "|"+
                port+
                "|"+
                password
            )



    # SS

    if node.startswith("ss://"):

        m=re.search(
            r'@([^:]+):(\d+)',
            node
        )

        if m:

            server,port=m.groups()

            return (
                "ss|"
                +server+
                "|"+
                port
            )



    # VMESS

    if node.startswith("vmess://"):

        return node[:150]



    # HY

    if node.startswith(
        (
        "hysteria://",
        "hy2://"
        )
    ):

        return node.split("#")[0]



    return None




def extract_nodes(text):

    nodes=[]


    for line in text.splitlines():

        line=line.strip()


        if line.startswith(
            (
            "vless://",
            "vmess://",
            "ss://",
            "trojan://",
            "hysteria://",
            "hy2://"
            )
        ):

            nodes.append(line)


    return nodes




def main():


    print("读取节点...")


    if not os.path.exists(INPUT):

        print(
            "不存在:",
            INPUT
        )

        return



    with open(
        INPUT,
        encoding="utf-8"
    ) as f:

        raw=f.read()



    print(
        "原始长度:",
        len(raw)
    )



    nodes=extract_nodes(raw)


    print(
        "发现节点:",
        len(nodes)
    )



    result=[]

    seen=set()



    for node in nodes:


        key=node_key(node)


        if key is None:

            continue



        if key not in seen:

            seen.add(key)

            result.append(node)




    print(
        "去重后:",
        len(result)
    )



    # 删除旧文件

    if os.path.exists(OUTPUT):

        os.remove(OUTPUT)



    os.makedirs(
        "output",
        exist_ok=True
    )



    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:


        for node in result:

            f.write(
                node+"\n"
            )



    print(
        "输出完成:",
        OUTPUT
    )


if __name__=="__main__":

    main()

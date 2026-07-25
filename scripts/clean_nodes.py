import os
import re


INPUT = "output/raw_nodes.txt"
OUTPUT = "output/nodes.txt"


def get_key(node):

    node=node.strip()

    # VLESS UUID
    if node.startswith("vless://"):
        m=re.search(
            r'vless://([^@]+)@([^:]+):(\d+)',
            node
        )
        if m:
            uuid,server,port=m.groups()
            return f"vless|{server}|{port}|{uuid}"


    # VMESS
    if node.startswith("vmess://"):
        return node[:120]


    # SS
    if node.startswith("ss://"):
        m=re.search(
            r'@([^:]+):(\d+)',
            node
        )
        if m:
            server,port=m.groups()
            return f"ss|{server}|{port}"


    # Trojan
    if node.startswith("trojan://"):
        m=re.search(
            r'@([^:]+):(\d+)',
            node
        )
        if m:
            server,port=m.groups()
            return f"trojan|{server}|{port}"


    return node[:100]



def main():

    print("读取节点...")


    with open(INPUT,"r",encoding="utf8") as f:
        data=f.read()


    nodes=[]


    for line in data.splitlines():

        line=line.strip()

        if (
            line.startswith(
            (
            "vless://",
            "vmess://",
            "ss://",
            "trojan://",
            "hysteria://",
            "hy2://"
            ))
        ):
            nodes.append(line)



    print("发现节点:",len(nodes))


    result=[]

    seen=set()


    for n in nodes:

        key=get_key(n)

        if key not in seen:

            seen.add(key)
            result.append(n)



    print("去重后:",len(result))


    os.makedirs(
        "output",
        exist_ok=True
    )


    with open(
        OUTPUT,
        "w",
        encoding="utf8"
    ) as f:

        for n in result:
            f.write(n+"\n")


    print(
        "输出完成",
        OUTPUT
    )


if __name__=="__main__":
    main()

import re
import os


INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "output/nodes.txt"


def extract_nodes(text):

    patterns = [

        r"(vmess://[^\s]+)",
        r"(vless://[^\s]+)",
        r"(trojan://[^\s]+)",
        r"(ss://[^\s]+)",
        r"(hysteria://[^\s]+)",
        r"(hy2://[^\s]+)"

    ]

    nodes=[]

    for p in patterns:
        nodes += re.findall(p,text)


    return nodes



def node_key(node):

    """
    核心去重
    不看名字
    """

    try:

        # 去掉名字
        base=node.split("#")[0]

        return base

    except:

        return node



def main():

    print("读取节点...")


    if not os.path.exists(INPUT_FILE):
        print("没有nodes.txt")
        return


    text=open(
        INPUT_FILE,
        encoding="utf-8",
        errors="ignore"
    ).read()


    print(
        "原始长度:",
        len(text)
    )


    nodes=extract_nodes(text)


    print(
        "发现节点:",
        len(nodes)
    )



    result=[]

    seen=set()


    for n in nodes:

        key=node_key(n)

        if key not in seen:

            seen.add(key)
            result.append(n)



    print(
        "去重后:",
        len(result)
    )



    os.makedirs(
        "output",
        exist_ok=True
    )


    # 注意这里必须w
    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:


        for n in result:

            f.write(n+"\n")



    print(
        "输出完成:",
        OUTPUT_FILE
    )



if __name__=="__main__":
    main()

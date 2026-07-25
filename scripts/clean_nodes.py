import requests
import os


SOURCE_FILE = "config/sources.txt"
OUTPUT_FILE = "output/nodes.txt"


def download(url):
    try:
        r = requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent":"Mozilla/5.0"
            }
        )

        if r.status_code == 200:
            return r.text.splitlines()

    except Exception as e:
        print("失败:",url,e)

    return []


def main():

    nodes=[]


    with open(
        SOURCE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        urls=[
            x.strip()
            for x in f
            if x.strip()
        ]


    for url in urls:

        print("抓取:",url)

        data=download(url)

        nodes.extend(data)



    print(
        "抓取总数:",
        len(nodes)
    )


    # 去重
    clean=list(
        set(
            x.strip()
            for x in nodes
            if x.strip()
        )
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

import requests
import os


sources="sources.txt"

output="output/raw_nodes.txt"


headers={
    "User-Agent":
    "Mozilla/5.0"
}



def main():


    if not os.path.exists(sources):

        print("没有 sources.txt")

        return



    with open(
        sources,
        encoding="utf-8"
    ) as f:

        urls=[
            x.strip()
            for x in f.readlines()
            if x.strip()
        ]



    all_nodes=[]


    print("发现订阅数量:",len(urls))


    for url in urls:


        try:

            print("===================")

            print("下载:",url)


            r=requests.get(
                url,
                headers=headers,
                timeout=30
            )


            print(
                "状态:",
                r.status_code
            )


            print(
                "长度:",
                len(r.text)
            )


            if len(r.text)>10:

                all_nodes.append(
                    r.text
                )


        except Exception as e:


            print(
                "错误:",
                e
            )



    os.makedirs(
        "output",
        exist_ok=True
    )


    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:


        f.write(
            "\n".join(all_nodes)
        )


    print(
        "最终写入:",
        output
    )



if __name__=="__main__":

    main()

import requests
import os
import base64


SOURCES = "config/sources.txt"

OUTPUT = "output/raw_nodes.txt"


headers = {
    "User-Agent": "Mozilla/5.0"
}



def try_decode_base64(text):

    result=[]

    try:

        clean=text.replace(
            "\n",
            ""
        ).replace(
            "\r",
            ""
        )

        data=base64.b64decode(
            clean + "==="
        ).decode(
            "utf-8",
            errors="ignore"
        )


        if "://" in data:

            result.append(data)

    except:

        pass


    return result



def main():


    os.makedirs(
        "output",
        exist_ok=True
    )


    if not os.path.exists(SOURCES):

        print(
            "没有sources.txt"
        )

        return



    urls=[]


    with open(
        SOURCES,
        encoding="utf-8"
    ) as f:

        for line in f:

            line=line.strip()

            if line:

                urls.append(line)



    print(
        "订阅数量:",
        len(urls)
    )



    nodes=[]



    for url in urls:


        try:


            print(
                "抓取:",
                url
            )


            r=requests.get(
                url,
                headers=headers,
                timeout=30
            )


            print(
                "状态:",
                r.status_code,
                "长度:",
                len(r.text)
            )



            text=r.text



            nodes.append(text)



            nodes.extend(
                try_decode_base64(text)
            )



        except Exception as e:


            print(
                "失败:",
                e
            )



    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:


        for n in nodes:

            f.write(
                n+"\n"
            )



    print(
        "生成:",
        OUTPUT
    )



if __name__=="__main__":

    main()

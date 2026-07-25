import requests
import os
import base64


SOURCES="config/sources.txt"

OUTPUT="output/raw_nodes.txt"


headers={
    "User-Agent":"Mozilla/5.0"
}



def decode_base64(text):

    result=[]

    try:

        raw=text.replace("\n","").replace("\r","")

        data=base64.b64decode(
            raw+"==="
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


    if not os.path.exists(SOURCES):

        print(
            "没有找到:",
            SOURCES
        )

        return



    with open(
        SOURCES,
        encoding="utf-8"
    ) as f:

        urls=[
            x.strip()
            for x in f
            if x.strip()
        ]



    print(
        "订阅数量:",
        len(urls)
    )


    result=[]



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


            # 原始

            result.append(text)



            # base64

            result.extend(
                decode_base64(text)
            )



        except Exception as e:

            print(
                "失败:",
                e
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


        for item in result:

            f.write(
                item+"\n"
            )


    print(
        "生成:",
        OUTPUT
    )


if __name__=="__main__":

    main()

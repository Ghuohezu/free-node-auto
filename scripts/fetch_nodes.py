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

        print("没有sources.txt")

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


    for url in urls:


        try:

            print(
                "抓取:",
                url
            )


            r=requests.get(
                url,
                headers=headers,
                timeout=20
            )


            text=r.text


            all_nodes.append(text)



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
        output,
        "w",
        encoding="utf-8"
    ) as f:


        f.write(
            "\n".join(all_nodes)
        )



if __name__=="__main__":

    main()

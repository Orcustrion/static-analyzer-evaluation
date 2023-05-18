# -*- coding: utf-8 -*-

import json
import numpy

# 检测bug_data合法性及总结
with open('bug_data.json', 'r', encoding='utf-8') as json_file:
    bug_data=json.load(json_file)

cwe_476,cwe_119=0,0



product=dict()
commit=set()
sign=1

for i in bug_data.keys():
    value_i=bug_data[i]
    value_i["id"]=sign
    sign+=1
    
    if value_i["cwe"]=="CWE-476":
        cwe_476+=1
    elif value_i["cwe"]=="CWE-119":
        cwe_119+=1

    # 按产品分类统计
    if value_i["product"] not in product:
        product[value_i["product"]]=[]
    product[value_i["product"]].append(i)

    # 检查合法性
    # commit信息
    if value_i["CommitVersion"] not in commit:
        commit.add(value_i["CommitVersion"])
    else:
        print(value_i["CommitVersion"]," ",i," ",value_i["product"])


    
# 输出文件
f=open("test.txt","w",encoding='utf-8')
f.write("bug_data统计结果: \n")
f.writelines(["total ",str(len(bug_data)),"\n","cwe-476:",str(cwe_476),"  ","cwe-119:",str(cwe_119),"\n"])
for i in product.keys():
    f.writelines(["\n",i,"  cwe个数:",str(len(product[i])),"\n"])
    for j in product[i]:
        f.writelines(["   ",j,"\n"])

# 更改bug_data
with open('bug_data.json', 'w', encoding='utf-8') as json_file:
    json.dump(bug_data,json_file,indent=4
              )

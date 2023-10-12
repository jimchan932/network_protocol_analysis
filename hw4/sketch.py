import numpy as np
import hashlib
import socket
import os
currentPath = os.path.dirname(os.path.abspath(__file__))    # 获取当前路径
print(currentPath)
os.chdir( currentPath )
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

packets = scapy.rdpcap('100flow.pcap')
f =open("result.txt","w+")
# print >> f,name
palis=[[],[]]

for p in packets:
    try:
     dic =  {}
     dic["Protocol"] = p[1].proto
     dic["Destination"] = p[1].dst
     dic["Source"] = p[1].src
     dic["Sport"] = p[1].sport
     dic["Dport"] = p[1].dport
     palis[0].append(dic)
     palis[1].append(len(dic))
     
     # print >> f,p[1].proto, p[1].dst, p[1].src, p[2].sport, p[2].dport
    except AttributeError:
        continue
   # f.close()
    # p.show()



import numpy as np
import hashlib

class CountMinSketch:
    def __init__(self, width, depth):
        self.width = width
        self.depth = depth
        self.table = np.zeros((depth, width), dtype=int)

        self.hash_funcs = []
        for i in range(depth):
            self.hash_funcs.append(
                hashlib.sha256(str(i).encode()).digest()
            )

    def increment(self, item, count=1):
        for i in range(self.depth):
            hash_val = int.from_bytes(
                hashlib.sha256(self.hash_funcs[i] + str(item).encode()).digest(),
                byteorder='big'
            )
            idx = hash_val % self.width
            self.table[i][idx] += count

    def estimate(self, item):
        res = []
        for i in range(self.depth):
            hash_val = int.from_bytes(
                hashlib.sha256(self.hash_funcs[i] + str(item).encode()).digest(),
                byteorder='big'
            )
            idx = hash_val % self.width
            res.append(self.table[i][idx])
        return min(res)


pactype = []
len = []

cms = CountMinSketch(10, 5)
data = ['apple', 'banana', 'orange', 'apple', 'apple', 'pear']
numcount=0
for d in palis[0]:
    print(d)
    cms.increment(d)
    if pactype.count(str(d)) == 0:
        pactype.append(str(d))
        len.append(0)
    if pactype.count(str(d)) > 0:
        num=pactype.index(str(d))
        len[num]+=palis[1][numcount]
        
print(pactype)
#报文数据（通过算法计算流数量
#pactype为数据流，len为每个数据流的字节数
for d  in pactype:
    print(cms.estimate(d))
for a in len:
    print(a)


#测试数据
print(cms.estimate('apple'))
print(cms.estimate('banana'))
print(cms.estimate('orange'))
#具体影响：深度会影响到哈希结果的碰撞概率，深度越大就更精确（对低频影响较小）宽度为哈希数组，宽度越大越不容易碰撞
#流数会影响的结果的准确率，流数越多结果越容易偏大    负载量 = 数据量 / 时间（字节数）
# 主程序
if __name__ == '__main__':
    pass
    # # 替换FILENAME为你的包含五元组信息包的文件名
    # with open('./task.pcap', 'rb') as f:
    #     packet = f.read()
    #     five_tuple = extract_five_tuple(packet)
    #     print(five_tuple)  # 输出五元组

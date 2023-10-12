from scapy.all import *
from collections import Counter
import plotly

max_packet_length = 1514

packets = rdpcap('packet.pcapng')

packet_length_list = []

for pkt in packets:
    if IP in pkt and TCP in pkt and pkt[IP].dst != '192.168.137.108':
        pkt_len = len(pkt)
        print("%d "% pkt_len, end = '')
        pkt_len_lower = int(pkt_len / 100) * 100
        pkt_len_higher = pkt_len_lower + 100
        packet_length_list.append(pkt_len_lower)

random_sample_packet_length_list = random.sample(packet_length_list, k = 500)
#create an empty list to hold the count of ips
cnt = Counter()

for ip in random_sample_packet_length_list:
    cnt[ip] += 1


xyData = []
#sort data and create x and y
for ip, count in cnt.most_common():
    xyData.append((ip, count))

xyData.sort(key = lambda a : a[0])
print(xyData)    
xData = []
yData = []

for item in xyData:
    xData.append("%d - %d" % (item[0], item[0] + 100))
    yData.append(item[1])
    

# Create a graph
plotly.offline.plot({
    "data":[ plotly.graph_objs.Bar( x = xData, y = yData, text = yData) ]})

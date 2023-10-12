from scapy.all import *
from collections import Counter
import plotly


packets = rdpcap('packet.pcapng')

srcIP = []

for pkt in packets:
    if IP in pkt and TCP in pkt and pkt[IP].dst != '192.168.137.108':
        try:
            srcIP.append(pkt[IP].dst)
        except:
            pass

#create an empty list to hold the count of ips
cnt = Counter()

for ip in srcIP:
    cnt[ip] += 1

xData = []
yData = []

#sort data and create x and y
for ip, count in cnt.most_common():
  xData.append(ip)
  yData.append(count)
  
print(xData)
print(yData)
# Create a graph
plotly.offline.plot({
    "data":[ plotly.graph_objs.Bar( x = xData, y = yData) ]})

from scapy.all import *
from collections import Counter
import plotly


packets = rdpcap('packet.pcapng')

srcPort = []

for pkt in packets:
    if TCP in pkt and pkt[IP].src == '192.168.137.108':        
        srcPort.append(pkt[TCP].sport)    
    if UDP in pkt and pkt[IP].src == '192.168.137.108':        
        srcPort.append(pkt[UDP].sport)    
        
#create an empty list to hold the count of ips
cnt = Counter()

for port in srcPort:
    cnt[port] += 1

xData = []
yData = []

#sort data and create x and y
for port, count in cnt.most_common():
  xData.append(str(port))
  yData.append(count)
  
print(xData)
print(yData)
# Create a graph
plotly.offline.plot({
    "data":[ plotly.graph_objs.Bar( x = xData, y = yData) ]})

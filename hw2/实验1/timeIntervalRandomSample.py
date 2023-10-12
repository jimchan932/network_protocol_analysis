#!/usr/bin/env python3

from scapy.all import *
from collections import Counter
import plotly


packets = rdpcap('packet.pcapng')#Lists to hold packet info
timeIntervalList = []

first_arrived_flag = 0

for pkt in packets:
    
    if IP in pkt and TCP in pkt and pkt[IP].src == '222.200.254.38' and pkt[IP].dst == '192.168.137.108':        
        if first_arrived_flag == 0:
           oldPktTime = pkt.time
           first_arrived_flag = 1
        else:
           timeInterval = pkt.time - oldPktTime          
           oldPktTime = pkt.time
           timeIntervalList.append(timeInterval)

print(len(timeIntervalList))
sampledTimeIntervalList = random.sample(timeIntervalList, k = 500)
sampledTimeIntervalList.sort()        
cnt = Counter()

for timeInterval in sampledTimeIntervalList:
    cnt[str(timeInterval)] += 1 

xData = []
yData = []

#sort data and create x and y
for timeInterval, count in cnt.most_common():
  xData.append(timeInterval)
  yData.append(count)
  
# Create a graph
plotly.offline.plot({
    "data":[ plotly.graph_objs.Bar( x = xData, y = yData) ]})

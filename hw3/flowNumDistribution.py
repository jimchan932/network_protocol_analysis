from scapy.all import *
from collections import Counter
import plotly
import plotly.graph_objects as go
import plotly.offline as pyo
from plotly.offline import init_notebook_mode

packets = rdpcap('packet.pcapng')

# count the number of packets for each flow

network_flow_list = []
for pkt in packets:
    if IP in pkt and TCP in pkt:
        network_flow_list.append((pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport))
        

print("number of flows = %d" % len(network_flow_list))
packet_num_counter = Counter()
for flow in network_flow_list:
    packet_num_counter[flow] += 1

xyData = []
#sort data and create x and y
numToDisplay = 30
i = 0
for ip, count in packet_num_counter.most_common():
    if i > numToDisplay: break
    xyData.append((ip, count))
    i = i + 1
xData = []
yData = []

for item in xyData:
    xData.append("(%s, %s, %d, %d)" % (item[0][0], item[0][1], item[0][2], item[0][3]))
    yData.append(item[1])
    
# Create a graph

plotly.offline.plot({
    "data":[ plotly.graph_objs.Bar( x = xData, y = yData, text = yData) ]})


from scapy.all import *
from collections import Counter
import plotly
import plotly.graph_objects as go
import plotly.offline as pyo
from plotly.offline import init_notebook_mode

max_packet_length = 1514

packets = rdpcap('packet.pcapng')

packet_length_list = []

seq_counter = 0
flow_batch_size = 12
num_samples_per_batch = 3
sampledPackets = []

sample_batch = []
for pkt in packets:
    if seq_counter == flow_batch_size:
        sample_index_list = random.sample(range(0, flow_batch_size), num_samples_per_batch)
        for i in range(0, num_samples_per_batch):
            sampledPackets.append(sample_batch[sample_index_list[i]])
        seq_counter = 0
        sample_batch = []
    sample_batch.append(pkt)
    seq_counter = seq_counter + 1
    
for pkt in sampledPackets:
    if IP in pkt and TCP in pkt and pkt[IP].dst == '222.200.254.41' and pkt[IP].src == '192.168.137.108' and pkt[TCP].dport == 80 and pkt[TCP].sport == 38222:
        pkt_len = len(pkt)
        print("%d "% pkt_len, end = '')
        pkt_len_lower = int(pkt_len / 100) * 100
        pkt_len_higher = pkt_len_lower + 100
        packet_length_list.append(pkt_len_lower)

#create an empty list to hold the count of ips
cnt = Counter()

for ip in packet_length_list:
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


from scapy.all import *
from collections import Counter
import plotly
import plotly.graph_objects as go
import plotly.offline as pyo
from plotly.offline import init_notebook_mode

packets = rdpcap('task.pcap')

flow_list = []

for pkt in packets:
    if IP in pkt and TCP in pkt:
        flow_list.append((pkt.time, len(pkt), pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, TCP))

with open("flow_list.txt", "w") as writeFile:
    for time, length, srcIP, destIP, srcPort, destPort, protocol in flow_list:
        writeFile.write("%s%s%d%d%s\n" % (srcIP, destIP, srcPort, destPort, "TCP"))
writeFile.close()

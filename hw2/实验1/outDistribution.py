#!/usr/bin/env python3
from scapy.all import *
import plotly
from datetime import datetime
import pandas as pd#Read the packets from file
packets = rdpcap('packet.pcapng')#Lists to hold packet info
pktBytes=[]
pktTimes=[] #Read each packet and append to the lists.
for pkt in packets:
    if IP in pkt and TCP in pkt and (pkt[IP].dst == '222.200.254.38' and pkt[IP].src == '192.168.137.108'):        
        pktTime = datetime.fromtimestamp(float(pkt.time))
        #Then convert to a format we like
        pktTimes.append(pkt.time)
        pktBytes.append(pkt[IP].len)           #First we need to covert Epoch time to a datetime

print(pktBytes)
#This converts list to series
bytes = pd.Series(pktBytes).astype(int)
print(bytes)
#Convert the timestamp list to a pd date_time


#Create the dataframe
df  = pd.DataFrame({"Bytes": bytes, "Times":pktTimes})

#set the date from a range to an timestamp
df = df.set_index('Times')

#Create a new dataframe of 2 second sums to pass to plotly
df2=df.resample('2S').sum()

#Create the graph
plotly.offline.plot({
    "data":[plotly.graph_objs.Scatter(x=df2.index, y=df2['Bytes'])],    "layout":plotly.graph_objs.Layout(title="Bytes over Time ",
        xaxis=dict(title="Time"),
        yaxis=dict(title="Bytes"))})

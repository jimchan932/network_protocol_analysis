from scapy.all import *
from collections import Counter
import plotly
import plotly.graph_objects as go
import plotly.offline as pyo
from plotly.offline import init_notebook_mode
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import SVC
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

def filter_flow(src_ip, dst_ip, src_port, dst_port, transport_protocol, packet_list, max_num_flows = 15000):
    flow_data_list = []
    flow_counter = 0
    for packet in packet_list:
        if IP in packet and transport_protocol in packet and
        packet[IP].src == src_ip and packet[IP].dst == dst_ip and
        packet[transport_protocol].sport == src_port and packet[transport_protocol].dport == dst_port:       
            flow_data_list.append([packet.time, len(packet[transport_protocol].payload)])
            flow_counter = flow_counter + 1
            if flow_counter == max_num_flows:
                break     
    return flow_data_list


# features:
# x1: mean interarrival time
# x2: mean payload / max payload
def add_features(feature_list, label_list,flow_data_list, class_name):
    window_features = []
    num_flows = len(flow_data_list)
    num_features_added = 0
    for i in range(num_flows):
        window_features.append(flow_data_list[i])
        window_size = len(window_features)    
        if(window_size == 16 or (i == num_flows - 1)):
            # compute features
            mean_interarrival_time = 0
            mean_payload = 0
            arrival_time_list = []
            max_payload = 0
            for features in window_features:
                arrival_time_list.append(features[0])
                mean_payload = mean_payload + features[1]
                if(max_payload < features[1]):
                    max_payload = features[1]
                    
            mean_payload = mean_payload / window_size
            for i in range(window_size-1):
                mean_interarrival_time = mean_interarrival_time + (arrival_time_list[i+1] - arrival_time_list[i])
            mean_interarrival_time = mean_interarrival_time / (window_size-1)
            window_features = window_features[8:]
            feature_list.append([mean_interarrival_time, max_payload])
            label_list.append(class_name)
            num_features_added = num_features_added + 1
    return num_features_added
                                                                 
if __name__ == '__main__':
    feature_list = []
    label_list = []
    youtube_packets = rdpcap('youtube_flows.pcapng')
    flow_data_list_1 = filter_flow('58.176.217.144', '192.168.128.72', 443, 64511, UDP, youtube_packets)
    num_features_1 = add_features(feature_list, label_list, flow_data_list_1, "youtube")
    print(num_features_1)
    
    game_packets = rdpcap('game_flows.pcapng')
    flow_data_list_2 = filter_flow('117.162.37.59','172.26.32.132', 16285, 49669, UDP, game_packets)
    num_features_2 = add_features(feature_list, label_list, flow_data_list_2, "gaming")
    print(num_features_2)
    
    school_packets = rdpcap('school.pcapng')
    flow_data_list_3_1 = filter_flow('202.116.81.230','192.168.128.102', 443, 57608, TCP, school_packets)
    num_features_3_1 = add_features(feature_list, label_list, flow_data_list_3_1, "other")
    flow_data_list_3_2 = filter_flow('202.116.81.230','192.168.128.102', 443, 57607, TCP, school_packets)
    num_features_3_2 = add_features(feature_list, label_list, flow_data_list_3_2, "other")
    flow_data_list_3_3 = filter_flow('202.116.81.230','192.168.128.102', 443, 57580, TCP, school_packets)
    num_features_3_3 = add_features(feature_list, label_list, flow_data_list_3_3, "other")
    flow_data_list_3_4 = filter_flow('202.116.81.230','192.168.128.102', 443, 57545, TCP, school_packets)
    num_features_3_4 = add_features(feature_list, label_list, flow_data_list_3_4, "other")
    flow_data_list_3_5 = filter_flow('202.116.81.230','192.168.128.102', 443, 57578, TCP, school_packets)
    num_features_3_5 = add_features(feature_list, label_list, flow_data_list_3_5, "other")
    flow_data_list_3_6 = filter_flow('202.116.81.230','192.168.128.102', 443, 57609, TCP, school_packets)
    num_features_3_6 = add_features(feature_list, label_list, flow_data_list_3_6, "other")
    flow_data_list_3_7 = filter_flow('202.116.81.230','192.168.128.102', 443, 57612, TCP, school_packets)
    num_features_3_7 = add_features(feature_list, label_list, flow_data_list_3_7, "other")        
    num_features_3 = num_features_3_1 + num_features_3_2 + num_features_3_3 + num_features_3_4 + num_features_3_5 + num_features_3_6 + num_features_3_7
    print(num_features_3)
    
    streaming_packets =rdpcap('streaming.pcapng')
    flow_data_list_4 = filter_flow('99.181.91.31', '192.168.128.102', 443, 56444, TCP, streaming_packets)
    num_features_4 = add_features(feature_list, label_list, flow_data_list_4, "other")
    print(num_features_4)    

    ecommerce_packets = rdpcap('ecommerce.pcapng')
    flow_data_list_5_1 = filter_flow('13.225.103.133', '192.168.128.102', 443, 65020, TCP, ecommerce_packets)
    num_features_5_1 = add_features(feature_list, label_list, flow_data_list_5_1, "other")
    flow_data_list_5_2 = filter_flow('13.225.103.133', '192.168.128.102', 443, 64892, TCP, ecommerce_packets)
    num_features_5_2 = add_features(feature_list, label_list, flow_data_list_5_2, "other")
    flow_data_list_5_3 = filter_flow('13.225.103.133', '192.168.128.102', 443, 65024, TCP, ecommerce_packets)
    num_features_5_3 = add_features(feature_list, label_list, flow_data_list_5_3, "other")      
    num_features_5 = num_features_5_1 + num_features_5_2 + num_features_5_3
    print(num_features_5)  

    X_train, X_test, y_train, y_test = train_test_split(feature_list, label_list, test_size = 0.2)
    clf = OneVsRestClassifier(SVC()).fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    labels = ['youtube','gaming', 'other']
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    sns.heatmap(cm, annot=True, fmt='g', xticklabels=labels,yticklabels=labels)
    plt.ylabel('Prediction', fontsize=13)
    plt.xlabel('Actual', fontsize=13)
    plt.title('Confusion Matrix', fontsize=17)
    plt.show()
    #classification_report
    FP = cm.sum(axis=0) - np.diag(cm)  
    FN = cm.sum(axis=1) - np.diag(cm)
    TP = np.diag(cm)
    TN = cm.sum() - (FP + FN + TP)

    # Sensitivity, hit rate, recall, or true positive rate
    TPR = TP/(TP+FN)
    # Specificity or true negative rate
    TNR = TN/(TN+FP) 
    # Precision or positive predictive value
    PPV = TP/(TP+FP)
    # Negative predictive value
    NPV = TN/(TN+FN)
    # Fall out or false positive rate
    FPR = FP/(FP+TN)
    # False negative rate
    FNR = FN/(TP+FN)
    # False discovery rate
    FDR = FP/(TP+FP)
    F1_Score = TP / (TP + 0.5*(FP+FN))
    # Overall accuracy
    ACC = (TP+TN)/(TP+FP+FN+TN)

    for i in range(3):
        print("False positive rate (%s): %f" % (labels[i], FPR[i]))
        print("Accuracy score (%s): %f" % (labels[i], ACC[i]))
        print("F1-score (%s): %f\n\n" % (labels[i], F1_Score[i]))

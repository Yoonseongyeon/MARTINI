import sys
import struct
import os
from scapy.all import sniff, IP, TCP
import time

def compute_metrics(tp, tn, fp, fn):
    recall = tp / (tp + fn) if (tp + fn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0
    f1score = 2 * (precision * recall) / (precision + recall) if (precision + recall) else 0
    return recall, precision, accuracy, f1score

def handle_pkt(pkt, counters):
    if IP in pkt:
        
        tos = pkt[IP].tos
        label1 = (tos >> 6) & 0x03
        label2 = (tos >> 4) & 0x03
        prediction1 = (tos >> 2) & 0x03
        prediction2 = tos & 0x03

        print('tos : ', tos)
        print('lable1 : ', label1)
        print('lable2 : ', label2)
        print('prediction1 : ', prediction1)
        print('prediction2 : ', prediction2)
        # pkt.show()

        # Task 1: 2-class classification
        if label1 == prediction1:
            if label1 == 1:
                counters['task1']['TP'] += 1
            else:
                counters['task1']['TN'] += 1
        else:
            if label1 == 1:
                counters['task1']['FN'] += 1
            else:
                counters['task1']['FP'] += 1

        # Task 2: 3-class classification
        if label2 == prediction2:
            counters['task2']['TP'][label2] += 1
        else:
            counters['task2']['FP'][prediction2] += 1
            counters['task2']['FN'][label2] += 1

        # Updating TN for Task 2 is a bit tricky as it involves all classes other than the current one
        for i in range(3):
            if i != label2:
                counters['task2']['TN'][i] += 1
        
        end_time = time.time()
        with open("end_times.txt", "a") as file:
            file.write(f"{end_time}\n")

def print_metrics(counters):
    # Task 1 Metrics
    tp1, tn1, fp1, fn1 = counters['task1'].values()
    recall1, precision1, accuracy1, f1score1 = compute_metrics(tp1, tn1, fp1, fn1)
    print(f"Task 1 - Recall: {recall1}, Precision: {precision1}, Accuracy: {accuracy1}, F1 Score: {f1score1}")

    # Task 2 Metrics
    accuracy2_total = 0
    for i in range(3):
        tp2, tn2, fp2, fn2 = [counters['task2'][key][i] for key in ['TP', 'TN', 'FP', 'FN']]
        recall2, precision2, accuracy2, f1score2 = compute_metrics(tp2, tn2, fp2, fn2)
        accuracy2_total += accuracy2
        print(f"Task 2 Class {i} - Recall: {recall2}, Precision: {precision2}, Accuracy: {accuracy2}, F1 Score: {f1score2}")

    print(f"Task 2 Average Accuracy: {accuracy2_total / 3}")

def main():
    iface = 'eth0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    counters = {
        'task1': {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0},
        'task2': {'TP': [0, 0, 0], 'FP': [0, 0, 0], 'FN': [0, 0, 0], 'TN': [0, 0, 0]}
    }
    sniff(iface=iface, prn=lambda x: handle_pkt(x, counters))
    print_metrics(counters)

if __name__ == '__main__':
    main()
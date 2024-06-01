from scapy.all import *
from scapy.all import PcapReader, sendp, Ether, IP
from time import sleep
from collections import Counter
import time

def read_labels(filename):
    with open(filename) as f:
        return [int(line.strip()) for line in f]

label1_values = read_labels("te_lb1.txt")
label2_values = read_labels("te_lb2.txt")

count_0 = label1_values.count(0)
count_1 = label1_values.count(1)

count_2 = label2_values.count(0)
count_3 = label2_values.count(1)
count_4 = label2_values.count(2)

tos_counts = {0: 0, 16: 0, 32: 0, 64: 0, 80: 0, 96: 0}

with PcapReader("test.pcap") as pcap_reader:
    pkts = [pkt for pkt in pcap_reader]

for i, pkt in enumerate(pkts):
    if IP in pkt:
        label1 = label1_values[i % len(label1_values)]
        label2 = label2_values[i % len(label2_values)]
        tos = (label1 << 6) | (label2 << 4)
        pkt[IP].tos = tos

for pkt in pkts:
    if IP in pkt:
        tos = pkt[IP].tos
        if tos in tos_counts:
            tos_counts[tos] += 1

print(f"label1 - 0s: {count_0}, 1s: {count_1}")
print(f"label2 - 0s: {count_2}, 1s: {count_3}, 2s: {count_4}")

print("TOS value frequencies:")
for tos, count in tos_counts.items():
    print(f"TOS = {tos}: {count} times")

print("Sending packets...")

# max = 49160
num_packets_to_send = min(len(pkts), 49160)

for i in range(num_packets_to_send):

    sendp(pkts[i], iface='eth0', verbose=False)

    print(pkts[i][IP].tos)
    # pkts[i].show()

print(f"{num_packets_to_send} packets have been sent.")

print("Done.")

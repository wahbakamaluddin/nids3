import scapy.all as scapy
import time

scapy.sniff(iface="wlp0s20f3", prn=lambda x: print(x.time), count=1)
print(time.time())
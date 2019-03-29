from scapy.all import *
import pandas as pd
import numpy as np
import sys
import socket 
import os
import csv
    

c = 0
LAST_TIME = 0.0
MAX_READS = 100
data = dict()

def increment():
    global c
    c = c+1

def stopfilter(x):
     global c
     if c == MAX_READS:
         return True
     else:
         return False

def checkTime(x):
    global LAST_TIME
    if LAST_TIME == 0.0:
        val = 0       
    else:
        val = (x-LAST_TIME)
    LAST_TIME = x
    return val
        

def fields_extraction(x):                                                   #each loop for sniff do this
    global dict
    if IP in x:                                                         #if IP is a valid request, do this
        #eval_writer.writerow([x[IP].src,x[IP].dst,x[IP].len,x.time])       #write this data to csv
        increment()  
        if TCP in x:
            n = (x[IP].src, x[TCP].sport,x[IP].dst,x[TCP].dport,"tcp")
            if n in data:
                data[n] += 1
            else:
                data[n] = 1
        if UDP in x:
            n = (x[IP].src, x[UDP].sport,x[IP].dst,x[UDP].dport,"udp")
            if n in data:
                data[n] += 1
            else:
                data[n] = 1

                

with open('eval.csv','a',newline='') as eval:                               #open csv in append mode
    eval_writer = csv.writer(eval, delimiter=',')                           #setup line writing
    

sniff(prn = fields_extraction,stop_filter = stopfilter)
max = 0
bestkey = ()
for key, value in data.items():
    if value > max:
        max = value
        bestkey = key
n = (bestkey[2],bestkey[3],bestkey[0],bestkey[1],bestkey[4])       
print("Highest Flow: ",bestkey, " Count: ",data[bestkey])
if n in data:
    print("Pair Flow: ",n, " Count: ",data[n])
d = 0
print()
for key, value in data.items():
    print(key, "\t Count:",data[key])



    

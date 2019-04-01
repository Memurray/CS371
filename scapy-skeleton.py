from scapy.all import *
import pandas as pd
import numpy as np
import sys
import socket 
import os
import csv    

c = 0
MAX_READS = 100
timeDict = dict()
data = dict()

#Basic global + 1 operation
def increment():
    global c
    c = c+1

#Define rules for when sniffer stops
def stopfilter(x):
     global c
     if c == MAX_READS:
         return True
     else:
         return False

#Keeps track of last time seen that flow
def checkTime(currentTime,n): 
    if n in timeDict:  #if seen flow before, time is just current time  - last time seen flow
           val = (currentTime-timeDict[n]) 
    else:  #if never seen flow, time since last is just 0
           val = 0
    timeDict[n] = currentTime  #update last time seen of the flow
    return val  
  
#Update feature averages stored in tuple   (Right now hard coded for 1 counter variable and 2 feature values (Length and time since last seen) )
def updateTuple(old,new):  
    counter = old[0]
    out1 = counter+1
    out2 = (old[1]*counter + new[0])/(counter+1.0)
    out3 = (old[2]*counter + new[1])/(counter+1.0)
    return (out1,out2,out3)   

#Looks through data, finding flow with highest occurance count  
def getBestFlow():
    max = 0
    bestkey = ()
    for key, value in data.items():
        if value[0] > max:
            max = value[0]
            bestkey = key          
    print("Highest Flow: ",bestkey, " Count: ",data[bestkey]) 
    return bestkey

#Flips input flow and returns information if it exists
def getPairFlow(flow):
    n = (flow[2],flow[3],flow[0],flow[1],flow[4]) 
    if n in data:
        print("Pair Flow: ",n, " Count: ",data[n])
    d = 0
    print()
    for key, value in data.items():
        print(key, "\t Count:",data[key])


def fields_extraction(x):         #each loop for sniff do this
    global dict
    if IP in x:               #if IP is a valid request, do this
        #eval_writer.writerow([x[IP].src,x[IP].dst,x[IP].len,x.time])       #write this data to csv
        increment()  
        n=()
        if TCP in x:
            n = (x[IP].src, x[TCP].sport,x[IP].dst,x[TCP].dport,"tcp")         #Generate flow id for TCP   
        if UDP in x:
            n = (x[IP].src, x[UDP].sport,x[IP].dst,x[UDP].dport,"udp")         #Generate flow id for UDP  

        if n in data:
            data[n] = updateTuple(data[n],(x[IP].len,checkTime(x.time,n)))  #Update the feature averages
        else:
            data[n] = (1,x[IP].len,checkTime(x.time,n))  #Set initial feature values
            

                
with open('eval.csv','a',newline='') as eval:                #open csv in append mode
    eval_writer = csv.writer(eval, delimiter=',')            #setup line writing
    
sniff(prn = fields_extraction,stop_filter = stopfilter)
best = getBestFlow()
getPairFlow(best)

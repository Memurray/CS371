from scapy.all import *
import pandas as pd
import numpy as np
import sys
import socket 
import os
import csv    

#Basic global + 1 operation
def increment():
    global c
    c = c+1

#Define rules for when sniffer stops
#This method was a very simple way to stop run when highest flow hits a threshold without checking highest flow after every read
def stopfilter(x):
     global c
     if c == MAX_READS:  #If counter is at threshold 
         max= getBestFlowCount()  
         if max == MAX_READS:  #check highest flow count
            return True  #if highest flow is at threshold, end
         else:
            c = max  # set counter to highest flow count
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
    out4 = (old[3]*counter + new[2])/(counter+1.0)
    out5 = (old[4]*counter + new[3])/(counter+1.0)
    return (out1,out2,out3,out4,out5)   

#Looks through data, finding flow with highest occurance count  
def getBestFlow():
    max = 0
    bestkey = ()
    for key, value in data.items():
        if value[0] > max:
            max = value[0]
            bestkey = key          
    #print("Highest Flow: ",bestkey, " Data: ",data[bestkey]) 
    return bestkey

def getBestFlowCount():
    max = 0
    bestkey = ()
    for key, value in data.items():
        if value[0] > max:
            max = value[0]          
    return max

#Flips input flow and returns information if it exists
def getPairFlow(flow):
    n = (flow[2],flow[3],flow[0],flow[1],flow[4]) 
    if n in data:
        print("Pair Flow: ",n, " Count: ",data[n])
    d = 0
    print()
    for key, value in data.items():
        print(key, "\t Count:",data[key])

def printToFile(flow,features,label):
    with open('eval.csv','a',newline='') as eval:        #open csv in append mode
        eval_writer = csv.writer(eval, delimiter=',')    #setup line writing
        eval_writer.writerow([flow,features[1],features[2],features[3],features[4],label])  #write this data to csv
        

def fields_extraction(x):         #each loop for sniff do this
    global dict
    if IP in x:               #if IP is a valid request, do this
        increment()  
        n=()
        if TCP in x:
            n = (x[IP].src, x[TCP].sport,x[IP].dst,x[TCP].dport,"tcp")         #Generate flow id for TCP   
        if UDP in x:
            n = (x[IP].src, x[UDP].sport,x[IP].dst,x[UDP].dport,"udp")         #Generate flow id for UDP  

        if n in data:
            data[n] = updateTuple(data[n],(x[IP].len,checkTime(x.time,n),x[IP].ttl,x[IP].frag))  #Update the feature averages
        else:
            data[n] = (1,x[IP].len,checkTime(x.time,n),x[IP].ttl,x[IP].frag)  #Set initial feature values           

                
for i in range(25):
    c = 0
    MAX_READS = 1000
    timeDict = dict()
    data = dict()   
    sniff(prn = fields_extraction,stop_filter = stopfilter)
    best = getBestFlow()
    #getPairFlow(best)
    printToFile(best,data[best],4)

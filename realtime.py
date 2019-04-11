from scapy.all import *
import pandas as pd
import numpy as np
import sys
import socket 
import os
import csv   
import warnings
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree

warnings.filterwarnings('ignore')
df = pd.read_csv("eval.csv", header=None)
columns_list = ['flow_id','Protocol', 'Len Avg', 'Len Max', 'Len Min','Time between packets','Time to Live','Outbound/Inbound', 'Pair Len' ,'label']
df.columns = columns_list
features = ['Protocol', 'Len Avg', 'Len Max', 'Len Min','Time between packets','Time to Live','Outbound/Inbound','Pair Len']

X = df[features]
y = df['label']
acc_scores = 0,
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25)
clf = tree.DecisionTreeClassifier()
clf.fit(X_train, y_train)

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
    if old[2] > new[0]:
        out3 = old[2]
    else:
        out3 = new[0]
    if old[3] < new[0]:
        out4 = old[3]
    else:
        out4 = new[0]
    out5 = (old[4]*counter + new[1])/(counter+1.0)
    out6 = (old[5]*counter + new[2])/(counter+1.0)
    return (out1,out2,out3,out4,out5,out6)   

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
    value = (1,0)
    if n in data:
        #print("Pair Flow: ",n, " Count: ",data[n])
        value = (data[n][0],data[n][1])
    return value

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
            data[n] = updateTuple(data[n],(x[IP].len,checkTime(x.time,n),x[IP].ttl))  #Update the feature averages
        else:
            data[n] = (1,x[IP].len,x[IP].len,x[IP].len,checkTime(x.time,n),x[IP].ttl)  #Set initial feature values           

textOutput = ["Web Browsing","Video Streaming","Video Conference","File Download"]

for i in range(25):
    c = 0    
    MAX_READS = 50
    timeDict = dict()
    data = dict()   
    sniff(prn = fields_extraction,stop_filter = stopfilter)
    best = getBestFlow()
    pair_flow_metrics = getPairFlow(best)  
    if best[0][0:3]  == "10." or best[0][0:4]  == "192.":
        flowratio = data[best][0]/pair_flow_metrics[0]
    else:
        flowratio = pair_flow_metrics[0]/data[best][0]
    
    proto = 1
    if best[4] == "udp":
        proto = 0
         
    prediction = clf.predict([[proto,data[best][1],data[best][2],data[best][3],data[best][4],data[best][5],flowratio,pair_flow_metrics[1]]])
    print(textOutput[int(prediction)-1])

#   1.)     Web Browsing (Wikipedia)
#   2.)     Video Streaming (Youtube)
#   3.)     Video Conference (Skype)
#   4.)     File Download (Downloading Ubuntu)
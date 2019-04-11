import warnings
import pandas as pd 
import numpy as np
import csv 
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree

def printToFile(d0,d1,d2,d3,d4):
    with open('MLoutput.csv','a',newline='') as eval:        #open csv in append mode
        eval_writer = csv.writer(eval, delimiter=',')    #setup line writing
        eval_writer.writerow([d0,d1,d2,d3[0],d3[1],d3[2],d3[3],d4])  #write this data to csv

warnings.filterwarnings('ignore')
df = pd.read_csv("eval.csv", header=None)
columns_list = ['flow_id','Protocol', 'Len Avg', 'Len Max', 'Len Min','Time between packets','Time to Live','Outbound/Inbound', 'Pair Len' ,'label']
df.columns = columns_list
features = ['Protocol', 'Len Avg', 'Len Max', 'Len Min','Time between packets','Time to Live','Outbound/Inbound','Pair Len']

X = df[features]
y = df['label']
printToFile("Test Type","Accuracy","Precision",["Label 1 Precision","Label 2 Precision","Label 3 Precision","Label 4 Precision"],"F1 Score")
acc_scores = 0,

def processCLF(clf,MLtype):
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    y_score = clf.score(X_test, y_test)
    print('Accuracy: ', y_score)

    precision = precision_score(y_pred, y_test, average='macro')
    print('Precision score: {0:0.2f}'.format(precision))

    per_class_precision = precision_score(y_pred, y_test, average=None)
    print('Per-class precision score:', per_class_precision)

    f1 = f1_score(y_test, y_pred, average='macro')
    print('F1 score:',f1)
    print()  
    printToFile(MLtype,y_score,precision,per_class_precision, f1) 


for i in range(0, 10):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25)

    #Decision Trees
    clf = tree.DecisionTreeClassifier()
    processCLF(clf,"DTC")

for i in range(0, 10):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25)

    clf = clf = MLPClassifier()
    processCLF(clf,"MPC")

for i in range(0, 10):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25)

    clf = SVC(gamma='auto')     #SVC USE THIS
    clf = LinearSVC()  #Linear SVC)
    processCLF(clf,"SVC")   
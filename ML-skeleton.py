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


df = pd.read_csv("eval.csv", header=None)
# You might not need this next line if you do not care about losing information about flow_id etc. All you actually need to
# feed your machine learning model are features and output label.
columns_list = ['flow_id','Protocol', 'Len Avg', 'Len Max', 'Len Min','Time between packets','Outbound/Inbound', 'label']
df.columns = columns_list
features = ['Protocol', 'Len Avg', 'Len Max', 'Len Min','Time between packets','Outbound/Inbound']

X = df[features]
y = df['label']

acc_scores = 0
for i in range(0, 10):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25)

    #Decision Trees
    clf = tree.DecisionTreeClassifier()
    clf.fit(X_train, y_train)

    # Neural network (MultiPerceptron Classifier)
    #clf = MLPClassifier()
    #clf.fit(X_train, y_train)

    #SVM's
    # clf = SVC(gamma='auto')     #SVC USE THIS
    # clf = LinearSVC()  #Linear SVC
    # clf.fit(X_train, y_train) 


    #here you are supposed to calculate the evaluation measures indicated in the project proposal (accuracy, F-score etc)
    y_pred = clf.predict(X_test)
    y_score = clf.score(X_test, y_test)
    print('Accuracy: ', y_score)

    # Compute the average precision score
    micro_precision = precision_score(y_pred, y_test, average='micro')
    print('Micro-averaged precision score: {0:0.2f}'.format(
          micro_precision))

    macro_precision = precision_score(y_pred, y_test, average='macro')
    print('Macro-averaged precision score: {0:0.2f}'.format(
          macro_precision))

    per_class_precision = precision_score(y_pred, y_test, average=None)
    print('Per-class precision score:', per_class_precision)

    print('F1 score:',f1_score(y_test, y_pred, average='macro'))
    print()     
          

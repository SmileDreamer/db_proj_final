# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'untitled.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QWidget, QLineEdit, QMessageBox
from PyQt5.QtCore import QRegExp
from PyQt5.QtGui import QRegExpValidator
from gui.mainwindow import *
import requests
import json

class Loginwindow(QtWidgets.QWidget):
    def __init__(self):
        super(Loginwindow, self).__init__()
        #self.setupUi(self)
        self.setObjectName("Login")
        self.resize(452, 350)
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.textEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(130, 50, 281, 51))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.textEdit.setFont(font)
        self.textEdit.setObjectName("textEdit")
        # password
        self.textEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.textEdit_2.setGeometry(QtCore.QRect(130, 150, 281, 51))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.textEdit_2.setFont(font)
        self.textEdit_2.setObjectName("textEdit_2")
        self.textEdit_2.setEchoMode(QLineEdit.Password)
        regx = QRegExp("^[0-9A-Za-z]{15}$")  # 为给定的模式字符串构造一个正则表达式对象。
        # 构造一个验证器，该父对象接受与正则表达式匹配的所有字符串。这里的父对象就是QLineEdit对象了。匹配是针对整个字符串; 例如：如果正则表达式是[A-Fa-f0-9]+将被视为^[A-Fa-f0-9]+$。
        validator = QRegExpValidator(regx, self.textEdit_2)
        # 将密码输入框设置为仅接受符合验证器条件的输入。 这允许您对可能输入的文本设置任何约束条件。因此我们这里设置的就是符合上面描述的三种约束条件。
        self.textEdit_2.setValidator(validator)

        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(70, 260, 111, 41))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(self.login)
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(260, 260, 111, 41))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_2.clicked.connect(self.register)
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(30, 60, 91, 41))
        font = QtGui.QFont()
        font.setFamily("Adobe Arabic")
        font.setPointSize(16)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(30, 160, 91, 41))
        font = QtGui.QFont()
        font.setFamily("Adobe Arabic")
        font.setPointSize(16)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        #self.setCentralWidget(self.centralwidget)
        #self.statusbar = QtWidgets.QStatusBar(MainWindow)
        #self.statusbar.setObjectName("statusbar")
        #MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Login"))
        self.pushButton.setText(_translate("MainWindow", "登陆"))
        self.pushButton_2.setText(_translate("MainWindow", "注册"))
        self.label.setText(_translate("MainWindow", "用户名"))
        self.label_2.setText(_translate("MainWindow", "密码"))

    def login(self):
        name = self.textEdit.text()
        password = self.textEdit_2.text()
        # username, password你的用户名和密码
        print("[DEBUG]Login with name [%s] and password [%s]"%(name, password))
        if (len(name) == 0 or len(password) == 0):
            QMessageBox.warning(self, "错误", "用户名或密码为空！", QMessageBox.Yes)
            return
        files = [
            ('json', ("action", json.dumps({"action": "login", "param": {"username": name, "password": password}}),
                      'application/json'))
        ]
        #登陆处理
        try:
            r = requests.post("http://172.18.95.74:8002/login", files=files)
            contect = r.content

            # 登陆成功
            self.hide()

            self.new_ui = MainWindow()
            self.new_ui.show()

        except Exception as err:
            print(format(err))

    def register(self):
        print("Register")
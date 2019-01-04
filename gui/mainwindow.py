# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QWidget, QLineEdit, QMessageBox
from PyQt5.QtCore import QRegExp
from PyQt5.QtGui import QRegExpValidator
import requests
import json

class MainWindow(QtWidgets.QWidget):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.setObjectName("Main")
        self.resize(1024, 768)
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")

        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(910, 10, 93, 31))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(self.get_list_from_dir)

        # 目录
        self.dirEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.dirEdit.setGeometry(QtCore.QRect(20, 10, 881, 31))
        self.dirEdit.setObjectName("textEdit")
        self.dirEdit.setText("/user/root")

        # 文件列表
        self.listView = QtWidgets.QListWidget(self.centralwidget)
        self.listView.setGeometry(QtCore.QRect(20, 60, 761, 681))
        self.listView.setObjectName("listView")

        # load test
        self.listView.addItem("file_1")
        self.listView.addItem("file_2")
        self.listView.addItem("file_3")
        #self.listView.doubleClicked(i).
        # load test

        # 文件属性
        self.textEdit_2 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_2.setGeometry(QtCore.QRect(800, 60, 201, 681))
        self.textEdit_2.setObjectName("textEdit_2")
        self.textEdit_2.setEnabled(False) # 禁止选定，从而避免编辑

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "MainWindow"))
        self.pushButton.setText(_translate("Dialog", "进入"))
        self.dirEdit.setWhatsThis(_translate("Dialog", "<html><head/><body><p>目录</p></body></html>"))
        self.listView.setWhatsThis(_translate("Dialog", "<html><head/><body><p>文件列表</p></body></html>"))

    def setToken(self, token):
        self.token = token

    def get_list_from_dir(self):
        current_dir = self.dirEdit.text()
        files = [
            ('json', ("action", json.dumps({
                "action": "read_dir",
                "token": self.token,
                "param":
                    {"dir_root": current_dir,
                     "dir_read_offset": 0,
                     "dir_read_num": 999}}),
            'application/json'))
        ]
        r = requests.post("http://172.18.95.74:8002/file", files=files)
        contect = json.loads(r.content)
        if contect['status'] != 0:
            QMessageBox.warning(self, "错误", "无法打开该文件夹！", QMessageBox.Yes)
            return
        self.listView.clear()
        for _name in contect['data']['entries']:
            self.listView.addItem(_name)


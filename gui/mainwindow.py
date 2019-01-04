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
        self.filelist = []
        root_dir = "/user/root"

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
        self.current_dir = root_dir
        self.dirEdit.setText(root_dir)

        # 文件列表
        self.listView = QtWidgets.QListWidget(self.centralwidget)
        self.listView.setGeometry(QtCore.QRect(20, 60, 761, 681))
        self.listView.setObjectName("listView")
        self.listView.doubleClicked.connect(self.item_doubleclick)

        # 文件属性
        self.FileElement = QtWidgets.QTextEdit(self.centralwidget)
        self.FileElement.setGeometry(QtCore.QRect(800, 60, 201, 601))
        self.FileElement.setObjectName("textEdit_2")
        #self.FileElement.setEnabled(False) # 禁止选定，从而避免编辑

        # 下载按钮
        self.download_button = QtWidgets.QPushButton(self.centralwidget)
        self.download_button.setGeometry(QtCore.QRect(800, 670, 191, 31))
        self.download_button.setObjectName("pushButton_2")

        # 上传按钮
        self.upload_button = QtWidgets.QPushButton(self.centralwidget)
        self.upload_button.setGeometry(QtCore.QRect(800, 710, 191, 31))
        self.upload_button.setObjectName("pushButton_3")

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "MainWindow"))
        self.pushButton.setText(_translate("Dialog", "进入"))
        self.dirEdit.setWhatsThis(_translate("Dialog", "<html><head/><body><p>目录</p></body></html>"))
        self.listView.setWhatsThis(_translate("Dialog", "<html><head/><body><p>文件列表</p></body></html>"))
        self.download_button.setText(_translate("Dialog", "下载文件"))
        self.upload_button.setText(_translate("Dialog", "上传文件"))

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
        try:
            r = requests.post("http://172.18.95.74:8002/file", files=files)
        except Exception as err:
            print(format(err))
            return
        contect = json.loads(r.content)
        if contect['status'] != 0:
            QMessageBox.warning(self, "错误", "无法打开该文件夹！", QMessageBox.Yes)
            return
        self.current_dir = current_dir
        self.listView.clear()
        self.filelist.clear()
        for _name in contect['data']['entries']:
            self.listView.addItem(_name)
            self.filelist.append(_name)

    def item_doubleclick(self, qtindex):
        index = qtindex.row()
        if (index >= len(self.filelist)):
            return
        selected_filename = self.filelist[index]
        # 文件夹
        if selected_filename[0] == '/':
            current_dir = self.dirEdit.text()
            current_dir += selected_filename[1:]
            self.dirEdit.setText(current_dir)
            self.get_list_from_dir()
            return
        # 文件
        files = [
            ('json', ("action", json.dumps({
                "action": "read_meta",
                "token": self.token,
                "param":
                    {"dir_root": self.current_dir,
                     "file_name": selected_filename}}),
                      'application/json'))
        ]
        try:
            r = requests.post("http://172.18.95.74:8002/file", files=files)
        except Exception as err:
            print(format(err))
            return
        contect = json.loads(r.content)
        if contect['status'] == 0:
            text = ""
            for data_key in contect['data']:
                text += data_key
                text += ": "
                if type(contect['data'][data_key]) == type("string"):
                    text += contect['data'][data_key]
                else:
                    text += str(contect['data'][data_key])
                text += "\n"
            self.FileElement.setText(text)
        print(self.filelist[index])
        pass

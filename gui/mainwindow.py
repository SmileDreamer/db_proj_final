# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QWidget, QLineEdit, QMessageBox, QFileDialog
from PyQt5.QtCore import QRegExp
from PyQt5.QtGui import QRegExpValidator
import requests
import json

class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setObjectName("Main")

        self.filelist = []
        self.selected_name = ""
        self.selected_id = -1
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
        self.listView.clicked.connect(self.item_click)
        self.listView.doubleClicked.connect(self.item_doubleclick)

        # 文件属性
        self.FileElement = QtWidgets.QTextEdit(self.centralwidget)
        self.FileElement.setGeometry(QtCore.QRect(800, 140, 201, 471))
        self.FileElement.setObjectName("textEdit_2")

        # 删除按钮
        self.delete_button = QtWidgets.QPushButton(self.centralwidget)
        self.delete_button.setGeometry(QtCore.QRect(800, 630, 191, 31))
        self.delete_button.setObjectName("pushButton_2")
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self.delete_file)

        # 下载按钮
        self.download_button = QtWidgets.QPushButton(self.centralwidget)
        self.download_button.setGeometry(QtCore.QRect(800, 670, 191, 31))
        self.download_button.setObjectName("pushButton_2")
        self.download_button.setEnabled(False)
        self.download_button.clicked.connect(self.download_file)

        # 上传按钮
        self.upload_button = QtWidgets.QPushButton(self.centralwidget)
        self.upload_button.setGeometry(QtCore.QRect(800, 710, 191, 31))
        self.upload_button.setObjectName("pushButton_3")
        self.upload_button.clicked.connect(self.upload_file)

        # 命名
        self.naming = QtWidgets.QLineEdit(self.centralwidget)
        self.naming.setGeometry(QtCore.QRect(800, 60, 201, 31))
        self.naming.setObjectName("textEdit_3")

        # 创建文件夹按钮
        self.createdir_button = QtWidgets.QPushButton(self.centralwidget)
        self.createdir_button.setGeometry(QtCore.QRect(800, 100, 201, 31))
        self.createdir_button.setObjectName("pushButton_4")
        self.createdir_button.clicked.connect(self.create_dir)

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
        self.delete_button.setText(_translate("Dialog", "删除文件"))
        self.createdir_button.setText(_translate("Dialog", "创建文件夹"))

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
            QMessageBox.warning(self, "错误", contect['info'], QMessageBox.Yes)
            return
        self.current_dir = current_dir
        self.listView.clear()
        self.filelist.clear()
        # 根目录检查
        splited = self.current_dir.split("/")
        if (len(splited) > 3):
            self.listView.addItem("/..")
            self.filelist.append("/..")
        for _name in contect['data']['entries']:
            self.listView.addItem(_name)
            self.filelist.append(_name)

    def item_click(self, qtindex):
        index = qtindex.row()
        self.selected_id = index
        if (index >= len(self.filelist) or index < 0):
            self.selected_id = -1
            self.selected_name = ""
        else:
            self.selected_id = index
            self.selected_name = self.filelist[index]
        deletable = len(self.selected_name) > 0 and self.selected_name != '/..'
        downloadable = len(self.selected_name) > 0 and self.selected_name[0] != '/'
        self.download_button.setEnabled(downloadable)
        self.delete_button.setEnabled(deletable)
        # 获取meta
        if len(self.selected_name)> 0 and self.selected_name[0] != '/':
            files = [
                ('json', ("action", json.dumps({
                    "action": "read_meta",
                    "token": self.token,
                    "param":
                        {"dir_root": self.current_dir,
                         "file_name": self.selected_name}}),
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
            else:
                pass
        else:
            self.FileElement.setText("")

    def item_doubleclick(self, qtindex):
        index = qtindex.row()
        if (index >= len(self.filelist)):
            return
        selected_filename = self.filelist[index]
        # 文件夹
        if selected_filename[0] == '/':
            if selected_filename == '/..':
                current_dir = "/"
                splited = selected_filename.split("/")
                for dir_index in range(0,len(splited)-1):
                    dir = splited[dir_index]
                    if len(dir) == 0:
                        continue
                    current_dir += (dir + "/")
            else:
                current_dir = selected_filename
            self.dirEdit.setText(current_dir)
            self.get_list_from_dir()
            return
        pass

    def create_dir(self):
        dir_name = self.naming.text()
        if len(dir_name) == 0:
            return
        files = [
            ('json', ("action", json.dumps({
                "action": "create_dir",
                "token": self.token,
                "param":
                    {"dir_root": self.current_dir,
                     "dir_name": dir_name}}),
                      'application/json'))
        ]
        try:
            r = requests.post("http://172.18.95.74:8002/file", files=files)
        except Exception as err:
            print(format(err))
            return
        contect = json.loads(r.content)
        if contect['status'] != 0:
            QMessageBox.warning(self, "错误", contect['info'], QMessageBox.Yes)
            return
        self.naming.clear()
        self.dirEdit.setText(self.current_dir)
        self.get_list_from_dir()

    def upload_file(self):
        fullname = str(QFileDialog.getOpenFileName(self, 'Upload file')[0])
        if len(fullname) == 0:
            return
        splited_name = fullname.split('/')
        if len(splited_name) == 1:
            return
        last_name = splited_name[len(splited_name)-1]
        files = [
            ('file', (last_name,
                      open(fullname, 'rb'),
                      'application/octet')),
            ('json', ("action", json.dumps({
                "action": "upload_file",
                "token": self.token,
                "param":
                    {"dir_root": self.current_dir,
                     "file_name": last_name}}),
                      'application/json'))
        ]
        try:
            r = requests.post("http://172.18.95.74:8002/upload_file", files=files)
        except Exception as err:
            print(format(err))
            return
        contect = json.loads(r.content)
        if contect['status'] != 0:
            QMessageBox.warning(self, "错误", contect['info'], QMessageBox.Yes)
            return
        QMessageBox.information(self, "提示", contect['info'], QMessageBox.Yes)
        self.get_list_from_dir()

    def download_file(self):
        fullname = str(QFileDialog.getSaveFileName(self,'Download to:', self.selected_name[0]))
        if len(fullname) == 0:
            return
        splited_name = fullname.split('/')
        if len(splited_name) == 1:
            return
        last_name = splited_name[len(splited_name)-1]
        files = [
            ('json', ("action", json.dumps({
                "action": "read_file",
                "token": self.token,
                "param":
                    {"dir_root": self.current_dir,
                     "file_name": self.selected_name}}),
                      'application/json'))
        ]
        try:
            r = requests.post("http://172.18.95.74:8002/file", files=files)
        except Exception as err:
            print(format(err))
            return
        contect = json.loads(r.content)
        if contect['status'] != 0:
            QMessageBox.warning(self, "错误", contect['info'], QMessageBox.Yes)
            return
        file = open(fullname, 'wb')
        # write
        file.close()
        QMessageBox.information(self, "提示", contect['info'], QMessageBox.Yes)

    def delete_file(self):
        reply = QMessageBox.information(self, 'Confirm', "确认要删除吗？", QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        files = [
            ('json', ("action", json.dumps({
                "action": "del_file",
                "token": self.token,
                "param":
                    {"dir_root": self.current_dir,
                     "file_name": self.selected_name}}),
                      'application/json'))
        ]
        try:
            r = requests.post("http://172.18.95.74:8002/file", files=files)
        except Exception as err:
            print(format(err))
            return
        contect = json.loads(r.content)
        if contect['status'] != 0:
            QMessageBox.warning(self, "错误", contect['info'], QMessageBox.Yes)
            return
        QMessageBox.information(self, "提示", contect['info'], QMessageBox.Yes)
        self.get_list_from_dir()
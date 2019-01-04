# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

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

        # 目录
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(20, 10, 881, 31))
        self.textEdit.setObjectName("textEdit")

        # 文件列表
        self.listView = QtWidgets.QListView(self.centralwidget)
        self.listView.setGeometry(QtCore.QRect(20, 60, 761, 681))
        self.listView.setObjectName("listView")

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
        self.textEdit.setWhatsThis(_translate("Dialog", "<html><head/><body><p>目录</p></body></html>"))
        self.listView.setWhatsThis(_translate("Dialog", "<html><head/><body><p>文件列表</p></body></html>"))


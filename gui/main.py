# !/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
from PyQt5.QtCore import*
from PyQt5.QtWidgets import QWidget, QApplication, QGroupBox, QPushButton, QLabel, QHBoxLayout,  QVBoxLayout, QGridLayout, QFormLayout, QLineEdit, QTextEdit
from gui import login
from PyQt5 import QtCore, QtGui, QtWidgets

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = login.Ui_MainWindow()
    w = QtWidgets.QMainWindow()
    ex.setupUi(w)
    w.show()
    sys.exit(app.exec_())
# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ui/vfunc_markup_ui.ui'
#
# Created: Thu Jul  2 10:46:13 2015
#      by: pyside-uic 0.2.15 running on PySide 1.2.1
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(633, 360)
        self.verticalLayout_2 = QtGui.QVBoxLayout(Dialog)
        self.verticalLayout_2.setSpacing(1)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.treeWidget = QtGui.QTreeWidget(Dialog)
        self.treeWidget.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
        self.treeWidget.setRootIsDecorated(False)
        self.treeWidget.setUniformRowHeights(True)
        self.treeWidget.setExpandsOnDoubleClick(False)
        self.treeWidget.setColumnCount(4)
        self.treeWidget.setObjectName("treeWidget")
        self.treeWidget.headerItem().setText(0, "1")
        self.treeWidget.headerItem().setText(1, "2")
        self.treeWidget.headerItem().setText(2, "3")
        self.treeWidget.headerItem().setText(3, "4")
        self.treeWidget.header().setDefaultSectionSize(100)
        self.verticalLayout.addWidget(self.treeWidget)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)
        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Markup Vfunc", None, QtGui.QApplication.UnicodeUTF8))
        self.treeWidget.setSortingEnabled(True)


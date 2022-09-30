# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'UISample.ui'
#
# Created by: PyQt5 UI code generator 5.15.7
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label_eth_SelectNIC = QtWidgets.QLabel(self.centralwidget)
        self.label_eth_SelectNIC.setGeometry(QtCore.QRect(20, 20, 51, 21))
        self.label_eth_SelectNIC.setObjectName("label_eth_SelectNIC")
        self.label_eth_MAC = QtWidgets.QLabel(self.centralwidget)
        self.label_eth_MAC.setGeometry(QtCore.QRect(230, 20, 31, 21))
        self.label_eth_MAC.setObjectName("label_eth_MAC")
        self.label_eth_IPv4 = QtWidgets.QLabel(self.centralwidget)
        self.label_eth_IPv4.setGeometry(QtCore.QRect(20, 50, 51, 21))
        self.label_eth_IPv4.setObjectName("label_eth_IPv4")
        self.label_eth_IPv6 = QtWidgets.QLabel(self.centralwidget)
        self.label_eth_IPv6.setGeometry(QtCore.QRect(20, 80, 51, 16))
        self.label_eth_IPv6.setObjectName("label_eth_IPv6")
        self.comboBox_eth_SelectNIC = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox_eth_SelectNIC.setGeometry(QtCore.QRect(90, 20, 131, 21))
        self.comboBox_eth_SelectNIC.setObjectName("comboBox_eth_SelectNIC")
        self.lineEdit_eth_MAC = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_eth_MAC.setGeometry(QtCore.QRect(270, 20, 181, 21))
        self.lineEdit_eth_MAC.setObjectName("lineEdit_eth_MAC")
        self.lineEdit_eth_IPv4 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_eth_IPv4.setGeometry(QtCore.QRect(90, 50, 221, 21))
        self.lineEdit_eth_IPv4.setObjectName("lineEdit_eth_IPv4")
        self.lineEdit_eth_IPv6 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_eth_IPv6.setGeometry(QtCore.QRect(90, 80, 221, 21))
        self.lineEdit_eth_IPv6.setObjectName("lineEdit_eth_IPv6")
        self.label_eth_Linklocal = QtWidgets.QLabel(self.centralwidget)
        self.label_eth_Linklocal.setGeometry(QtCore.QRect(20, 110, 51, 21))
        self.label_eth_Linklocal.setObjectName("label_eth_Linklocal")
        self.lineEdit_eth_Linklocal = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_eth_Linklocal.setGeometry(QtCore.QRect(90, 110, 221, 21))
        self.lineEdit_eth_Linklocal.setObjectName("lineEdit_eth_Linklocal")
        self.label_eth_Gateway = QtWidgets.QLabel(self.centralwidget)
        self.label_eth_Gateway.setGeometry(QtCore.QRect(320, 50, 51, 21))
        self.label_eth_Gateway.setObjectName("label_eth_Gateway")
        self.lineEdit_eth_Gateway = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_eth_Gateway.setGeometry(QtCore.QRect(380, 50, 181, 21))
        self.lineEdit_eth_Gateway.setObjectName("lineEdit_eth_Gateway")
        self.lineEdit_eth_Gatewayv6 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_eth_Gatewayv6.setGeometry(QtCore.QRect(380, 80, 181, 21))
        self.lineEdit_eth_Gatewayv6.setObjectName("lineEdit_eth_Gatewayv6")
        self.label_eth_Gatewayv6 = QtWidgets.QLabel(self.centralwidget)
        self.label_eth_Gatewayv6.setGeometry(QtCore.QRect(320, 80, 51, 16))
        self.label_eth_Gatewayv6.setObjectName("label_eth_Gatewayv6")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 160, 761, 211))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.label_ARP_IP = QtWidgets.QLabel(self.tab)
        self.label_ARP_IP.setGeometry(QtCore.QRect(10, 50, 61, 16))
        self.label_ARP_IP.setObjectName("label_ARP_IP")
        self.label_ARP_TargetMAC = QtWidgets.QLabel(self.tab)
        self.label_ARP_TargetMAC.setGeometry(QtCore.QRect(10, 80, 61, 16))
        self.label_ARP_TargetMAC.setObjectName("label_ARP_TargetMAC")
        self.lineEdit_ARP_IP = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_ARP_IP.setGeometry(QtCore.QRect(90, 50, 161, 20))
        self.lineEdit_ARP_IP.setObjectName("lineEdit_ARP_IP")
        self.lineEdit_ARP_TargetMAC = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_ARP_TargetMAC.setGeometry(QtCore.QRect(90, 80, 161, 20))
        self.lineEdit_ARP_TargetMAC.setObjectName("lineEdit_ARP_TargetMAC")
        self.label_ARP_SendCount = QtWidgets.QLabel(self.tab)
        self.label_ARP_SendCount.setGeometry(QtCore.QRect(10, 110, 71, 16))
        self.label_ARP_SendCount.setObjectName("label_ARP_SendCount")
        self.lineEdit_ARP_SendCount = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_ARP_SendCount.setGeometry(QtCore.QRect(90, 110, 61, 20))
        self.lineEdit_ARP_SendCount.setObjectName("lineEdit_ARP_SendCount")
        self.pushButton_ARP_Send = QtWidgets.QPushButton(self.tab)
        self.pushButton_ARP_Send.setGeometry(QtCore.QRect(170, 110, 75, 23))
        self.pushButton_ARP_Send.setObjectName("pushButton_ARP_Send")
        self.groupBox_ARP_OPCode = QtWidgets.QGroupBox(self.tab)
        self.groupBox_ARP_OPCode.setGeometry(QtCore.QRect(10, 10, 241, 31))
        self.groupBox_ARP_OPCode.setObjectName("groupBox_ARP_OPCode")
        self.radioButton_ARP_Request = QtWidgets.QRadioButton(self.groupBox_ARP_OPCode)
        self.radioButton_ARP_Request.setGeometry(QtCore.QRect(60, 10, 83, 16))
        self.radioButton_ARP_Request.setChecked(True)
        self.radioButton_ARP_Request.setObjectName("radioButton_ARP_Request")
        self.radioButton_ARP_Reply = QtWidgets.QRadioButton(self.groupBox_ARP_OPCode)
        self.radioButton_ARP_Reply.setGeometry(QtCore.QRect(150, 10, 83, 16))
        self.radioButton_ARP_Reply.setObjectName("radioButton_ARP_Reply")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.lineEdit_NDP_IPv6 = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_NDP_IPv6.setGeometry(QtCore.QRect(90, 50, 161, 20))
        self.lineEdit_NDP_IPv6.setObjectName("lineEdit_NDP_IPv6")
        self.lineEdit_NDP_TargetMAC = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_NDP_TargetMAC.setGeometry(QtCore.QRect(90, 80, 161, 20))
        self.lineEdit_NDP_TargetMAC.setObjectName("lineEdit_NDP_TargetMAC")
        self.lineEdit_NDP_SendCount = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_NDP_SendCount.setGeometry(QtCore.QRect(90, 110, 61, 20))
        self.lineEdit_NDP_SendCount.setObjectName("lineEdit_NDP_SendCount")
        self.pushButton_NDP_Send = QtWidgets.QPushButton(self.tab_2)
        self.pushButton_NDP_Send.setGeometry(QtCore.QRect(170, 110, 75, 23))
        self.pushButton_NDP_Send.setObjectName("pushButton_NDP_Send")
        self.label_NDP_IPv6 = QtWidgets.QLabel(self.tab_2)
        self.label_NDP_IPv6.setGeometry(QtCore.QRect(10, 50, 61, 16))
        self.label_NDP_IPv6.setObjectName("label_NDP_IPv6")
        self.label_NDP_TargetMAC = QtWidgets.QLabel(self.tab_2)
        self.label_NDP_TargetMAC.setGeometry(QtCore.QRect(10, 80, 61, 16))
        self.label_NDP_TargetMAC.setObjectName("label_NDP_TargetMAC")
        self.label_NDP_SendCount = QtWidgets.QLabel(self.tab_2)
        self.label_NDP_SendCount.setGeometry(QtCore.QRect(10, 110, 71, 16))
        self.label_NDP_SendCount.setObjectName("label_NDP_SendCount")
        self.groupBox_NDP_OPCode = QtWidgets.QGroupBox(self.tab_2)
        self.groupBox_NDP_OPCode.setGeometry(QtCore.QRect(10, 10, 241, 31))
        self.groupBox_NDP_OPCode.setObjectName("groupBox_NDP_OPCode")
        self.radioButton_NDP_Request = QtWidgets.QRadioButton(self.groupBox_NDP_OPCode)
        self.radioButton_NDP_Request.setGeometry(QtCore.QRect(60, 10, 83, 16))
        self.radioButton_NDP_Request.setChecked(True)
        self.radioButton_NDP_Request.setObjectName("radioButton_NDP_Request")
        self.radioButton_NDP_Reply = QtWidgets.QRadioButton(self.groupBox_NDP_OPCode)
        self.radioButton_NDP_Reply.setGeometry(QtCore.QRect(150, 10, 83, 16))
        self.radioButton_NDP_Reply.setObjectName("radioButton_NDP_Reply")
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.pushButton_StressTest_DHCP = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_StressTest_DHCP.setGeometry(QtCore.QRect(160, 10, 75, 23))
        self.pushButton_StressTest_DHCP.setObjectName("pushButton_StressTest_DHCP")
        self.pushButton_StressTest_DHCPv6 = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_StressTest_DHCPv6.setGeometry(QtCore.QRect(240, 10, 75, 23))
        self.pushButton_StressTest_DHCPv6.setObjectName("pushButton_StressTest_DHCPv6")
        self.label_StressTest_SendCount = QtWidgets.QLabel(self.tab_3)
        self.label_StressTest_SendCount.setGeometry(QtCore.QRect(20, 10, 61, 16))
        self.label_StressTest_SendCount.setObjectName("label_StressTest_SendCount")
        self.lineEdit_StressTest_SendCount = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_StressTest_SendCount.setGeometry(QtCore.QRect(90, 10, 61, 20))
        self.lineEdit_StressTest_SendCount.setObjectName("lineEdit_StressTest_SendCount")
        self.label_StressTest_IPv4CIDR = QtWidgets.QLabel(self.tab_3)
        self.label_StressTest_IPv4CIDR.setGeometry(QtCore.QRect(20, 50, 61, 16))
        self.label_StressTest_IPv4CIDR.setObjectName("label_StressTest_IPv4CIDR")
        self.lineEdit_StressTest_CIDR = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_StressTest_CIDR.setGeometry(QtCore.QRect(90, 50, 351, 20))
        self.lineEdit_StressTest_CIDR.setObjectName("lineEdit_StressTest_CIDR")
        self.pushButton_StressTest_SendARP = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_StressTest_SendARP.setGeometry(QtCore.QRect(470, 50, 75, 23))
        self.pushButton_StressTest_SendARP.setObjectName("pushButton_StressTest_SendARP")
        self.lineEdit_StressTest_Prefix = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_StressTest_Prefix.setGeometry(QtCore.QRect(90, 90, 351, 20))
        self.lineEdit_StressTest_Prefix.setObjectName("lineEdit_StressTest_Prefix")
        self.label_StressTest_Prefix = QtWidgets.QLabel(self.tab_3)
        self.label_StressTest_Prefix.setGeometry(QtCore.QRect(20, 90, 61, 16))
        self.label_StressTest_Prefix.setObjectName("label_StressTest_Prefix")
        self.pushButton_StressTest_SendNDP = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_StressTest_SendNDP.setGeometry(QtCore.QRect(470, 90, 75, 23))
        self.pushButton_StressTest_SendNDP.setObjectName("pushButton_StressTest_SendNDP")
        self.tabWidget.addTab(self.tab_3, "")
        self.plainTextEdit_PrintMessage = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.plainTextEdit_PrintMessage.setGeometry(QtCore.QRect(30, 380, 741, 181))
        self.plainTextEdit_PrintMessage.setObjectName("plainTextEdit_PrintMessage")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "SendPacketTool"))
        self.label_eth_SelectNIC.setText(_translate("MainWindow", "SelectNIC"))
        self.label_eth_MAC.setText(_translate("MainWindow", "MAC"))
        self.label_eth_IPv4.setText(_translate("MainWindow", "IPv4"))
        self.label_eth_IPv6.setText(_translate("MainWindow", "IPv6"))
        self.label_eth_Linklocal.setText(_translate("MainWindow", "Linklocal"))
        self.label_eth_Gateway.setText(_translate("MainWindow", "Gateway"))
        self.label_eth_Gatewayv6.setText(_translate("MainWindow", "Gatewayv6"))
        self.label_ARP_IP.setText(_translate("MainWindow", "IP"))
        self.label_ARP_TargetMAC.setText(_translate("MainWindow", "Target MAC"))
        self.label_ARP_SendCount.setText(_translate("MainWindow", "Send Count"))
        self.lineEdit_ARP_SendCount.setText(_translate("MainWindow", "1"))
        self.pushButton_ARP_Send.setText(_translate("MainWindow", "Send"))
        self.groupBox_ARP_OPCode.setTitle(_translate("MainWindow", "OPCode"))
        self.radioButton_ARP_Request.setText(_translate("MainWindow", "Request"))
        self.radioButton_ARP_Reply.setText(_translate("MainWindow", "Reply"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "ARP"))
        self.lineEdit_NDP_SendCount.setText(_translate("MainWindow", "1"))
        self.pushButton_NDP_Send.setText(_translate("MainWindow", "Send"))
        self.label_NDP_IPv6.setText(_translate("MainWindow", "IPv6"))
        self.label_NDP_TargetMAC.setText(_translate("MainWindow", "Target MAC"))
        self.label_NDP_SendCount.setText(_translate("MainWindow", "Send Count"))
        self.groupBox_NDP_OPCode.setTitle(_translate("MainWindow", "OPCode"))
        self.radioButton_NDP_Request.setText(_translate("MainWindow", "Request"))
        self.radioButton_NDP_Reply.setText(_translate("MainWindow", "Reply"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "NDP"))
        self.pushButton_StressTest_DHCP.setText(_translate("MainWindow", "DHCP"))
        self.pushButton_StressTest_DHCPv6.setText(_translate("MainWindow", "DHCPv6"))
        self.label_StressTest_SendCount.setText(_translate("MainWindow", "SendCount"))
        self.lineEdit_StressTest_SendCount.setText(_translate("MainWindow", "70"))
        self.label_StressTest_IPv4CIDR.setText(_translate("MainWindow", "IPv4 CIDR"))
        self.lineEdit_StressTest_CIDR.setText(_translate("MainWindow", "192.168.1.0/24"))
        self.pushButton_StressTest_SendARP.setText(_translate("MainWindow", "Send"))
        self.lineEdit_StressTest_Prefix.setText(_translate("MainWindow", "2001:b030:2133:811::/64"))
        self.label_StressTest_Prefix.setText(_translate("MainWindow", "IPv6 Prefix"))
        self.pushButton_StressTest_SendNDP.setText(_translate("MainWindow", "Send"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainWindow", "Stress Test"))

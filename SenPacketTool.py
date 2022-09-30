from PyQt5 import QtCore, QtGui, QtWidgets
from NetPacketTools.packet_action import PacketAction
from scapy.all import get_working_ifaces,get_working_if,conf

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



        self.comboBox_eth_SelectNIC.addItems(self.GetNICAllName())
        self.comboBox_eth_SelectNIC.currentIndexChanged.connect(self.GetNICInfo)
        self.pushButton_ARP_Send.clicked.connect(self.SendARP)
        self.pushButton_NDP_Send.clicked.connect(self.SendNDP)
    
    def GetNICAllName(self) -> list[str]:
        NICs = get_working_ifaces()
        return [str(x.name) for x in NICs]
    
    def GetNICInfo(self) -> None:
        Nic = [x for x in get_working_ifaces() if self.comboBox_eth_SelectNIC.currentText() == x.name][0]
        self.lineEdit_eth_MAC.setText(str(Nic.mac))
        self.lineEdit_eth_IPv4.setText(str(Nic.ip))
        self.lineEdit_eth_Gateway.setText(str(conf.route.route('0.0.0.0')[2] ))
        IPv6Global = [x for x in Nic.ips[6] if '2001:' in x]
        if len(IPv6Global) == 0 : IPv6Global = ''
        else : IPv6Global = str(IPv6Global[0])
        self.lineEdit_eth_IPv6.setText(IPv6Global)
        Linklocal = [x for x in Nic.ips[6] if 'fe80::' in x]
        if len(Linklocal) == 0: Linklocal = ''
        else : Linklocal = Linklocal[0]
        self.lineEdit_eth_Linklocal.setText(str(Linklocal))
        Gatewayv6 = conf.route6.route('::')
        if len(Gatewayv6) < 3 :Gatewayv6 = Gatewayv6[2]
        else : Gatewayv6 = Gatewayv6[2]
        self.lineEdit_eth_Gatewayv6.setText(str(Gatewayv6))
    
    def SendARP(self) -> None:
        lan = PacketAction(str(self.comboBox_eth_SelectNIC.currentText()))
        if self.radioButton_ARP_Request.isChecked():
            r = None
            for i in range(int(self.lineEdit_ARP_SendCount.text())):
                r = lan.GetIPv4MAC(dstip=str(self.lineEdit_ARP_IP.text()))
                self.plainTextEdit_PrintMessage.appendPlainText(str(f'IP :{str(self.lineEdit_ARP_IP.text())}\nMAC : {str(r)}'))
        elif self.radioButton_ARP_Reply.isChecked():
            for i in range(int(self.lineEdit_ARP_SendCount.text())):
                lan.SendARPReply(IP=str(self.lineEdit_ARP_IP.text()),MAC=str(self.lineEdit_ARP_TargetMAC.text()))
                self.plainTextEdit_PrintMessage.appendPlainText(f'Send ARP Reply IP : {str(self.lineEdit_ARP_IP.text())}\n\
                MAC : {str(self.lineEdit_ARP_TargetMAC.text())}')
    
    def SendNDP(self) -> None :
        lan = PacketAction(str(self.comboBox_eth_SelectNIC.currentText()))
        if self.radioButton_NDP_Request.isChecked():
            r = None
            for i in range(int(self.lineEdit_NDP_SendCount.text())):
                r = lan.GetIPv6MAC(dstIP=str(self.lineEdit_NDP_IPv6.text()))
                self.plainTextEdit_PrintMessage.appendPlainText(str(f'IPv6 :{str(self.lineEdit_NDP_IPv6.text())}\nMAC : {str(r)}'))
        elif self.radioButton_NDP_Reply.isChecked():
            for i in range(int(self.lineEdit_NDP_SendCount.text())):
                lan.SendNA(IP=str(self.lineEdit_NDP_IPv6.text()),MAC=str(self.lineEdit_NDP_TargetMAC.text()))
                self.plainTextEdit_PrintMessage.appendPlainText(f'Send NDP Reply IPv6 : {str(self.lineEdit_NDP_IPv6.text())}\n\
                MAC : {str(self.lineEdit_NDP_TargetMAC.text())}')     



if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())


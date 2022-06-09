from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter
from NetPacketTools.packet_action_test import PacketRelated8021X
from CreateData import iprelated,macrelated
import time,csv,ipaddress


# lis = PacketListenFromFilter('乙太網路 3')
# lis.Sniffer(time=60)
# pass

#用封包計算 Auth-Message Hash
# testcase = PacketRelated8021X()
# # testcase.CreateCISCOExampleRadiusPacp(outputpath='D:/test.pcap')
# testcase.CalcuRespondAuthenticator(pcapfilepath='D:/1111.pcap',packetidx=1,secrectkey=b'pixis')
# testcase.CalcuProxyMessageAuthenticator(pcapfilepath='D:/radiusproxy.Pcap',packetidx=3,secrectkey=b'pixis')
# # testcase.CalculateHashFromPacket(pcapfilepath='D:/CISCOCoa.pcap',packetidx=0,secrectkey=b'pixis')
# pass


#偵測 Wi-fi 網斷的 ARP MAC
# lan1 = PacketAction('Wi-Fi')
# ipv4data = iprelated.CreateIPDataByCIDROrPrifix(f'{lan1.Ip}/24')
# for i in range(1,len(ipv4data)-1):
#     mac = lan1.GetIPv4MAC(str(ipv4data[i]))
#     if mac :
#         with open('ARPscan.txt','a') as file:
#             file.write(f'IP:{ipv4data[i]}, MAC:{mac} \n')
# pass


#產生大量的 IP 和 IPv6 和 MAC 資料成 CSV
# ipv6data = iprelated.CreateIPDataByCIDROrPrifix('2001:b030:2133:80b::11:0/112')
# macdata = macrelated.CreateMACData('AA0000000000',256)

# if ipv4data and ipv6data and macdata:
#     for i in range(1,255):
#         with open('output.csv','a') as file:
#             file.write(f'{ipv4data[i]},{ipv6data[i]},{macdata[i]} \n')
# pass



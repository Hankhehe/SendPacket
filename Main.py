from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter
from NetPacketTools.packet_action_test import PacketRelated8021X
from CreateData import iprelated,macrelated
import time


testcase = PacketRelated8021X()
testcase.CalculateHashFromPacket(pcapfilepath='D:/test.pcap',secrectkey=b'pixis')

# ipv4data = iprelated.CreateIPDataByCIDROrPrifix('192.168.11.0/24')
# ipv6data = iprelated.CreateIPDataByCIDROrPrifix('2001:b030:2133:80b::11:0/112')
# macdata = macrelated.CreateMACData('AA0000000000',256)

# if ipv4data and ipv6data and macdata:
#     for i in range(1,255):
#         with open('output.csv','a') as file:
#             file.write(f'{ipv4data[i]},{ipv6data[i]},{macdata[i]} \n')
# pass

lan1 = PacketAction('Wi-Fi')

# while True :
#     lan1.SendARPReply(IP='192.168.11.32',MAC='aa:00:00:00:00:00')
#     lan1.SendARPReply(IP='192.168.11.32',MAC='aa:00:00:00:00:01')
#     # time.sleep(1)

while True :
    lan1.SendARPReply(IP='192.168.11.32',MAC='aa:00:00:00:00:00')
    # time.sleep(1)

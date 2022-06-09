from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter
from NetPacketTools.packet_action_test import PacketRelated8021X
from CreateData import iprelated,macrelated
import time,csv

def SendIPconflict(ip:str) -> None:
    '''發送 IP 衝突'''
    while True :
        lan1.SendARPReply(IP=ip,MAC='aa:00:00:00:00:00')
        lan1.SendARPReply(IP=ip,MAC='aa:00:00:00:00:01')
        time.sleep(1)

def SendManyBroadcastOfARP() -> None:
    '''發送大量的 ARP Reply'''
    while True:
        lan1.SendARPReply(IP=lan1.Ip)

lan1 = PacketAction('乙太網路')
# SendIPconflict(ip='192.168.11.32')
# SendManyBroadcastOfARP()
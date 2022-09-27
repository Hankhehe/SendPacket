import time
from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter
from CreateData import iprelated,macrelated


def SendOnline() ->None:
    ipv4list = iprelated.CreateIPDataByCIDROrPrifix(cidr='172.17.0.0/17')
    ipv6list = iprelated.CreateIPDataByCIDROrPrifix(cidr='2001:b030:2133:811::/112')
    maclist = macrelated.CreateMACData(mac='AA0000000000',count=32768)
    while True :
        for i in range(1,5001):
            lan1.SendARPReply(IP=str(ipv4list[i]),MAC=maclist[i])
            lan1.SendNA(IP=str(ipv6list[i]),MAC=maclist[i])

def SendIPconflict(ip:str,mac1:str,mac2:str,count:int) -> None:
    '''發送 IP 衝突'''
    MACAddress1 = macrelated.ConvertMACbyPunctuation(mac=mac1,Punctuation=':')
    MACAddress2 = macrelated.ConvertMACbyPunctuation(mac=mac2,Punctuation=':')
    for i in range(count):
        lan1.SendARPReply(IP=ip,MAC=MACAddress1)
        lan1.SendARPReply(IP=ip,MAC=MACAddress2)
        time.sleep(1)

def SendIPv6Conflict(ipv6:str,mac1:str,mac2:str,count:int) -> None:
    '''發送 IPv6 衝突'''
    MACAddress1 = macrelated.ConvertMACbyPunctuation(mac=mac1,Punctuation=':')
    MACAddress2 = macrelated.ConvertMACbyPunctuation(mac=mac2,Punctuation=':')
    for i in range(count):
        lan1.SendNA(IP=ipv6,MAC=MACAddress1)
        lan1.SendNA(IP=ipv6,MAC=MACAddress2)
        time.sleep(1)

def SendManyBroadcastOfARP() -> None:
    '''發送大量的 ARP Reply'''
    while True:
        lan1.SendARPReply(IP=lan1.Ip)

lan1 = PacketAction('乙太網路')
# SendIPconflict(ip='192.168.11.32',mac1='aa0000000000',mac2='aa0000000001',count=3)
# SendIPv6Conflict(ipv6='2001:b030:2133:80b::11:32',mac1='aa0000000000',mac2='aa0000000001',count=3)
# SendManyBroadcastOfARP()
# lan1.SendNBNSResponse(name='Hank',workgroup=False) #發送主機名稱 by NBNS
# lan1.SendNBNSResponse(name='WORKGROUP',workgroup=True) #發送網域群組 by NBNS
# SendOnline() #發送大量 IP and IPv6 and MAC 的 ARP 和 NDP
while True :
    lan1.SendARPReply(IP='192.168.24.2',MAC='AAAAAAAAAAAA')
    time.sleep(1)
    # lan1.SendARPReply(IP='192.168.21.2',MAC='AACCCCCCCCCC')
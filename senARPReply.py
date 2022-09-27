from NetPacketTools.packet_action import PacketAction
import time

nicname = input('input Nic Name :')
TargIP = input('input Target IP :')
TargMAC = input('input Target MAC :')
waittime = input('input Wait time per sec :')
lan = PacketAction(nicname)
while True:
    lan.SendARPReply(IP=TargIP,MAC=TargMAC)
    time.sleep(int(waittime))
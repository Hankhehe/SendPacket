from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter
from CreateData import iprelated,macrelated

ipv4data = iprelated.CreateIPDataByCIDROrPrifix('192.168.11.1/22')
ipv6data = iprelated.CreateIPDataByCIDROrPrifix('2001:b030:2133:80b:192:168:11:1/108')
macdata = macrelated.CreateMACData('AA0000000000',1024)

if ipv4data and ipv6data and macdata:
    for i in range(1,1023):
        with open('output.csv','a') as file:
            file.write(f'{ipv4data[i]},{ipv6data[i]},{macdata[i]} \n')
pass
if ipv6data : 
    for i in ipv6data:
        print (iprelated.ConvertIPv6ShortToIPv6Full(str(i)))
mac = macrelated.CreateMACData('AA0000000000',100)

convertmac = macrelated.ConvertMACbyPunctuation('AA0000000000','-')
if convertmac:
    convertmac = convertmac.upper()
pass
lan1_ = PacketAction('Wi-Fi')

if ipv4data:
    for i in ipv4data:
        with open('output.csv','a') as file:
            file.write(f'IP: {i} , MAC: {lan1_.GetIPv4MAC(i)} \n')
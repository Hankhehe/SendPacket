from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter

lan1_ = PacketAction('Wi-Fi')
mac = lan1_.SendRA(flagM=1,flagO=1,Prefix='2001:b030:2133:80b::')
pass


from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter


lan1_ = PacketAction()
receivedIP = lan1_.GetIPfromDHCPv4(tranId=5,mac='cc:2f:71:20:ce:93')
pass


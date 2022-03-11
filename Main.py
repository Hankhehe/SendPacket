from ntpath import join
from xml.dom.pulldom import CHARACTERS
from NetPacketTools.packet_action import PacketAction
from NetPacketTools.packet_listen import PacketListenFromFilter
import re

lan1_ = PacketAction()
mac = lan1_.GetIPv6MAC('fe80::250:56ff:fe67:9d8f')
pass


import ipaddress

def CreateIPDataByCIDROrPrifix(ip:str) -> list | None:
    '''Create Data of range IP in IPv4 or IPv6'''
    ip = ipaddress.ip_interface(ip).network  # type: ignore
    return list(ipaddress.ip_network(ip))

def ConvertIPv6ShortToIPv6Full(ipv6:str) -> str | None:
      iplist = ipv6.split('::')
      if len(iplist) > 2 or len(ipv6.split(':')) > 8:
         return
      ipaddr = ['0000'] * 8
      preip = iplist[0].split(':')
      idx = 0
      for i in preip :
         ipaddr[idx] = i.zfill(4)
         idx += 1
      if len(iplist) == 2 :
         postip = iplist[1].split(':')
         if len(postip) > 4 : return
         idx = -1
         for i in postip[::-1] :
               ipaddr[idx] = i.zfill(4)
               idx -= 1
      return ':'.join(ipaddr)
    

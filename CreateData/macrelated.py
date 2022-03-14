import re

def CreateMACData(mac:str,count:int) -> list | None :
    '''It can result consecutive MAC list when input stared MAC Address'''
    mac = ''.join(re.split(':|-|\.',mac)).upper()
    if len(mac) != 12 : return
    try: macnum =  int(mac,16) 
    except Exception : return
    result = []
    for i in range(count) :
        result.append(hex(int( macnum + i))[2::].upper().zfill(12))
    return result

def ConvertMACbyPunctuation(mac:str ,Punctuation:str)->str | None :
    '''Covert to example aaaa.aaaa or aa:aa:aa:aa or aa-aa-aa-aa '''
    mac = ''.join(re.split(':|-|\.',mac)).upper()
    if len(mac) != 12 : return
    if Punctuation == '-' or Punctuation == ':' : 
        return Punctuation.join(re.findall(r'.{2}',mac)).lower()
    elif Punctuation == '.' :
        return  Punctuation.join(re.findall(r'.{4}',mac)).lower()
    else : return
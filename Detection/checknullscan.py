from Detection.searchiplist import searchIPsrclist
class checkNULLScan:
    """docstring for ClassName"""
    def __init__(self, _listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
        indexIP = searchIPsrclist(_listFrameEth, ipsource).listSIP
        self.check = 0
        if (len(indexIP) != 0):
            xft = len(indexIP)
            for x in range(0,xft-1):
                if (_listFrameEth[indexIP[x]].ipsourc == ipsource
                and _listFrameEth[indexIP[x]].flagfin == 0 
                and _listFrameEth[indexIP[x]].flagurg == 0 
                and _listFrameEth[indexIP[x]].flagpsh == 0
                and _listFrameEth[indexIP[x]].flagsyn == 0
                and _listFrameEth[indexIP[x]].flagrst == 0 
                and _listFrameEth[indexIP[x]].flagack == 0
                and _listFrameEth[indexIP[x]].count >= 5): 
                    self.check = 3
        else:
            listNullScan = 0
            for x in range(0,len(_listFrameEth)):
                if (_listFrameEth[x].ipsourc == ipsource 
                and _listFrameEth[x].flagfin == 1):
                    listNullScan += 1
            if listNullScan >= 10:
                self.check = 3
        
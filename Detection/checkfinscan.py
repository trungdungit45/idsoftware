from Detection.searchiplist import searchIPsrclist

class checkFINScan:
    """docstring for ClassName"""
    def __init__(self, _listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg): 
        self.check = 0
        if(flagsyn == 1
        or flagrst == 1
        or flagpsh == 1
        or flagack == 1
        or flagurg == 1):
            self.check = 0
        else:
            indexIP = searchIPsrclist(_listFrameEth, ipsource).listSIP
            if (len(indexIP) != 0):
                xft = len(indexIP)
                for x in range(0,xft):
                    if (_listFrameEth[indexIP[x]].ipsourc == ipsource
                    and _listFrameEth[indexIP[x]].flagfin == 1 
                    and _listFrameEth[indexIP[x]].flagurg == 0 
                    and _listFrameEth[indexIP[x]].flagpsh == 0
                    and _listFrameEth[indexIP[x]].flagsyn == 0
                    and _listFrameEth[indexIP[x]].flagrst == 0 
                    and _listFrameEth[indexIP[x]].flagack == 0
                    and _listFrameEth[indexIP[x]].count >= 5): 
                        self.check = 2
            else:
                listFinScan = 0
                for x in range(0,len(_listFrameEth)-1):
                    if (_listFrameEth[x].ipsourc == ipsource 
                    and _listFrameEth[x].flagfin == 1):
                        listFinScan += 1
                if listFinScan >= 4:
                    self.check = 2
        
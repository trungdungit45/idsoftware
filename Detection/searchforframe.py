class searchforFrame:
    def __init__(self, _frameHeader, ipsource, ipdesti, ipproto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
        self.search = -1
        for i in range(0,len(_frameHeader)-1):
            if(_frameHeader[i].ipsourc == ipsource 
            and _frameHeader[i].ipdesti == ipdesti 
            and _frameHeader[i].proto == ipproto 
            and _frameHeader[i].flagfin == flagfin 
            and _frameHeader[i].flagsyn == flagsyn 
            and _frameHeader[i].flagrst == flagrst 
            and _frameHeader[i].flagpsh == flagpsh 
            and _frameHeader[i].flagack == flagack 
            and _frameHeader[i].flagurg == flagurg):
                self.search = i
        
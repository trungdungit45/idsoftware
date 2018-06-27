class searchIpSrcTarlist:
	def __init__(self,_frameHeader, ipsource, iptarget):
	    self.listSIP = []
	    for x in range(0,len(_frameHeader)):
	        if (ipsource == _frameHeader[x].ipsourc
	        and iptarget == _frameHeader[x].ipdesti):
	            self.listSIP.append(x)
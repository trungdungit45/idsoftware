from Detection.searchipsrc import searchIPsrc
class checkUDPscan:
	"""docstring for """
	def __init__(self,_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
		self.check =  6
		if (searchIPsrc(_listFrameEth,ipsource).search) == -1:
			self.check =  0
		elif (_listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].ipsourc == ipsource and _listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].flagfin == 1 and _listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].flagurg == 1 and _listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].flagpsh ==1 and _listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].flagsyn == 0 and _listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].flagrst == 0 and _listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].flagack == 0 and _listFrameEth[searchIPsrc(_listFrameEth,ipsource).search].count >= 4):
			self.check =  6
		else:
			listXmax = 0
			for x in range(0,len(_listFrameEth)):
				if (_listFrameEth[x].ipsourc == ipsource and _listFrameEth[x].proto == 17):
					listXmax += 1
			if listXmax >= 5:
				self.check =  6
	    
		
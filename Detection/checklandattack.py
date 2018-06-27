from Detection.searchipsrc_tarlist import searchIpSrcTarlist
class checkLandAttack:
	def __init__(self, _listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
		indexIP = searchIpSrcTarlist(_listFrameEth, ipsource, ipdesti).listSIP
		self.check = 0
		xft = len(indexIP)
		if (xft != 0):
			if xft > 3:
				self.check = 5
			for x in range(0,xft):
				if _listFrameEth[x].count >= 5:
					self.check = 5       


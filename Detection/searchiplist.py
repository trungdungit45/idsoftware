class searchIPsrclist:
	"""docstring for ClassName"""
	def __init__(self,_frameHeader,ipsource):
	    self.listSIP = []
	    for x in range(0,len(_frameHeader)):
	        if (ipsource == _frameHeader[x].ipsourc):
	            self.listSIP.append(x)
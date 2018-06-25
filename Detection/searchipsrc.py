class searchIPsrc:
	"""docstring for ClassName"""
	def __init__(self,_frameHeader,ipsource):
		self.search =  -1
		for x in range(0,len(_frameHeader)):
			if (ipsource == _frameHeader[x].ipsourc):
				self.search =  x
	    
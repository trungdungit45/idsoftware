class blackIP:
	def readIP(self):
		f = open("Alert/blackIP.txt","r")
		list = []
		f1 = f.readlines()
		for x in f1:
			list.append(x)
		f.close()
		return list
	def appendIP(self, _ip):
		f = open("Alert/blackIP.txt","a+")
		f.write(_ip+'\n')
		f.close()


		
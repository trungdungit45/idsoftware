import datetime
from Detection.searchforframe import searchforFrame
from Detection.comparetime import compareTime
class checkpingofDead:
	def __init__(self,_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg,lentcp):
		self.check = 0
		index = searchforFrame(_listFrameEth, ipsource, ipdesti, proto, flagfin,flagsyn ,flagrst ,flagpsh ,flagack ,flagurg).search
		if index != -1:
			if (_listFrameEth[index].count >= 1000 and compareTime(datetime.datetime.now().strftime('%H%M%S'), _listFrameEth[index].time)._time < 1):
				if(lentcp >= 1400):
					self.check = 4
				else:
					self.check = 41
			else:
				self.check = 0

	    
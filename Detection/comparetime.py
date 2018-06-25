class compareTime:
	def __init__(self, timeStart, timeFinish):
		_timeStart = int(timeStart[0:2])*3600 + int(timeStart[2:4]) + int(timeStart[4:6])
		_timeFinish = int(timeFinish[0:2])*3600 + int(timeFinish[2:4]) + int(timeFinish[4:6])
		if (_timeFinish < _timeStart):
			self._time = ((_timeFinish + 86400) - _timeStart)
		else:
			self._time = (_timeFinish  - _timeStart)
from sendsms import sendSMS
import time 
#from Detection.comparetime import compareTime
import datetime
class compareTime:
	def __init__(self, timeStart, timeFinish):
		_timeStart = int(timeStart[0:2])*3600 + int(timeStart[2:4])*60 + int(timeStart[4:6])
		_timeFinish = int(timeFinish[0:2])*3600 + int(timeFinish[2:4])*60 + int(timeFinish[4:6])
		if (_timeFinish < _timeStart):
			self._time = ((_timeFinish + 86400) - _timeStart)
		else:
			self._time = (_timeFinish  - _timeStart)
def readIP():
        f = open("Log/snifflog.log","r")
        list = []
        f1 = f.readlines()
        for x in f1:
            list.append(x)
        f.close()
        return list
def checkLog(_listAlert, _listAlertStack):
	sender = '01633248977'
	ip = readIP()
	for ift in ip:
		_lineLog = ift
	#print(_lineLog)
	_warning, _root, _ipsource, _iptarget, _attack, _time, _timeStart, _date = _lineLog.split(':')
	strcontent = _timeStart +' WA' + _attack + ' ' + _time + ' from '+ _ipsource + ' to ' + _iptarget + ' ' + _date 
	if (strcontent not in _listAlert and strcontent not in _listAlertStack):
		_listAlert.append(strcontent)
		#print(strcontent)
	if (compareTime(_timeStart, datetime.datetime.now().strftime('%H%M%S'))._time <= 60
	and strcontent in _listAlert 
	and strcontent not in _listAlertStack):
			#print(_time)
			try:
				sendSMS(strcontent, sender)
				_listAlert.remove(strcontent)
				_listAlertStack.append(strcontent)       
			except:
				print('Check module sendsms')
def main():
	_listAlertStack = []
	_listAlert = []
	while True:
		checkLog(_listAlert, _listAlertStack)
		#time.sleep(1)
if __name__== '__main__':
    main()
	
	
	
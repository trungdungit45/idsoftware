#from sendsms import sendSMS
#from Detection.comparetime import compareTime
import datetime
import serial  
import time
def Sending(message, sender):
    SerialPort = serial.Serial("/dev/ttyUSB3",19200)
    SerialPort.write('AT+CMGF=1\r')
    time.sleep(1)
    SerialPort.write('AT+CMGS="'+sender+'"\r\n')
    time.sleep(1)
    SerialPort.write(message+"\x1A")
    time.sleep(1)
    print ('Bat dau gui tin, hay kt so dien thoai duoc gui')
    SerialPort.close()
def sendSMS(message, sender):
    Sending(message,sender)
class compareTime:
	def __init__(self, timeStart, timeFinish):
		_timeStart = int(timeStart[0:2])*3600 + int(timeStart[2:4]) + int(timeStart[4:6])
		_timeFinish = int(timeFinish[0:2])*3600 + int(timeFinish[2:4]) + int(timeFinish[4:6])
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
def checkLog():
	sender = '01652582138'
	ip = readIP()
	for ift in ip:
		_lineLog = ift
	_warning, _root, _ipsource, _iptarget, _attack, _time, _timeStart, _date = _lineLog.split(':')
	if (compareTime(_timeStart, datetime.datetime.now().strftime('%H%M%S'))._time <= 1):
		strcontent = _timeStart +' WA' + _attack + ' ' + _time + ' from '+ _ipsource + ' to ' + _iptarget + ' ' + _date 
		try:
			sendSMS(strcontent, sender)           
		except:
			print('Check module sendsms')
def main():
	while True:
		checkLog()
if __name__== '__main__':
    main()
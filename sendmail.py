from Alert.sendmail import send_message
from Detection.comparetime import compareTime
import datetime
def readIP():
        f = open("Log/snifflog.log","r")
        list = []
        f1 = f.readlines()
        for x in f1:
            list.append(x)
        f.close()
        return list
def checkLog():
    ip = readIP()
    for ift in ip:
        _lineLog = ift
    #print(_lineLog)
    _warning, _root, _ipsource, _iptarget, _attack, _time, _timeStart, _date = _lineLog.split(':')
    if (compareTime(_timeStart, datetime.datetime.now().strftime('%H%M%S'))._time <= 1):
        strcontent = _timeStart +' Warning Attack ' + _attack + ' ' + _time + ' from '+ _ipsource + ' to ' + _iptarget + ' ' + _date 
        #print(strcontent)
        try:
            send_message(strcontent, 'Warning System')
            #print('Sendmail Success')
        except:
            print('')
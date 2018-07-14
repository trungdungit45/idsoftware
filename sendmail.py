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
def checkLog(_listAlert, _listAlertStack):
    ip = readIP()
    for ift in ip:
        _lineLog = ift
    _warning, _root, _ipsource, _iptarget, _attack, _time, _timeStart, _date = _lineLog.split(':')
    strcontent = _timeStart +' WA' + _attack + ' ' + _time + ' from '+ _ipsource + ' to ' + _iptarget + ' ' + _date 
    if (strcontent not in _listAlert and strcontent not in _listAlertStack):
        _listAlert.append(strcontent)

    if (compareTime(_timeStart, datetime.datetime.now().strftime('%H%M%S'))._time <= 60
    and strcontent in _listAlert 
    and strcontent not in _listAlertStack):
        try:
            send_message(strcontent, 'Warning System')
            _listAlert.remove(strcontent)
            _listAlertStack.append(strcontent)  
        except:
            print('')
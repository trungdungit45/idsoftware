import socket
import datetime
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

from Alert.sendmail import send_message
from Alert.excuteblackip import blackIP
from Alert.writelog import writeLog

from Detection.checkxmasscan import checkXmasScan
from Detection.checkfinscan import checkFINScan
from Detection.checknullscan import checkNULLScan
from Detection.checkpingofdead import checkpingofDead
from Detection.comparetime import compareTime
from Detection.checklandattack import checkLandAttack
from Detection.checksqlinjection import checkSqlInjection
from Detection.checkudpscan import checkUDPscan
from Detection.searchipsrc_tarlist import searchIpSrcTarlist


from Struct.bcolor import bColors
from Struct.frameheader import frameHeader
from Struct.alertattack import alertAttack
from sendmail import checkLog

from threading import Thread

import sys

TAB_1 = '\t - '
DATA_TAB_2 = '\t\t '

def searchforframe(_frameHeader, ipsource, ipdesti, ipproto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
    for i in range(0,len(_frameHeader)):
        if(_frameHeader[i].ipsourc == ipsource and
        _frameHeader[i].ipdesti == ipdesti and
        _frameHeader[i].proto == ipproto and
        _frameHeader[i].flagfin == flagfin and
        _frameHeader[i].flagsyn == flagsyn and
        _frameHeader[i].flagrst == flagrst and
        _frameHeader[i].flagpsh == flagpsh and
        _frameHeader[i].flagack == flagack and
        _frameHeader[i].flagurg == flagurg):
            return i
    return -1
def AddtoFrame(_frameHeader, ipsource, ipdesti, count, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg ):
    index = searchforframe(_frameHeader, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
    indexIP = searchIpSrcTarlist(_frameHeader, ipsource, ipdesti).listSIP
    #print('Day la chieu dai ',len(indexIP))
    #printFrame(_frameHeader)
    #len(indexIP) == 0 and 
    if (index == -1):
        Frame = frameHeader()
        Frame.ipsourc = ipsource
        Frame.ipdesti = ipdesti
        Frame.time = datetime.datetime.now().strftime('%H%M%S')
        Frame.count = count
        Frame.proto = proto
        Frame.flagfin = flagfin
        Frame.flagsyn = flagsyn
        Frame.flagrst = flagrst
        Frame.flagpsh = flagpsh
        Frame.flagack = flagack
        Frame.flagurg = flagurg
       
        _frameHeader.append(Frame)
    else:
        _frameHeader[index].count += 1
        _frameHeader[index].time = datetime.datetime.now().strftime('%H%M%S')
def printFrame(_frameHeader):
    for i in range(0,len(_frameHeader)):
        print(i.__str__()+'  '+_frameHeader[i].proto.__str__()+ ' ' +_frameHeader[i].flagurg.__str__()+ ' '+_frameHeader[i].ipsourc.__str__() +' '+_frameHeader[i].ipdesti.__str__()+' '+_frameHeader[i].count.__str__()+' '+_frameHeader[i].time.__str__() + '\n')
    #print('hala')
#Xuat data Ethernet
def RefeshlistFrameTime(_listFrame):
    listF = []
    for i in range(0,len(_listFrame)-1):
        if (compareTime(datetime.datetime.now().strftime('%H%M%S'), _listFrame[i].time)._time > 5):
            #print('Day la thoi gian hien tai{0}\n'.format( datetime.datetime.now().strftime('%H%M%S')))
            if (_listFrame[i].count == 1):
                listF.append(i)
            else:
                _listFrame[i].count -= 1
    for x in range(len(listF),0):
        if (compareTime(datetime.datetime.now().strftime('%H%M%S'), _listFrame[x].time)._time > 5):
            _listFrame.remove(_listFrame[listF[x]])
def RefeshlistFrame(_listFrame, ipsource, ipdesti, proto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
    if (searchforframe(_listFrame, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg) != -1):
        _listFrame[searchforframe(_listFrame, ipsource, ipdesti, proto,
        flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)].count +=1
    listF = []
    for i in range(0,len(_listFrame)-1):
        if (compareTime(datetime.datetime.now().strftime('%H%M%S'), _listFrame[i].time)._time > 5):
            if (_listFrame[i].count == 1):
                listF.append(i)
            else:
                _listFrame[i].count -= 1
    for x in range(len(listF),0):
        if (compareTime(datetime.datetime.now().strftime('%H%M%S'), _listFrame[x].time)._time > 5):
            _listFrame.remove(_listFrame[listF[x]])
    return
def printSniffer(eth,count,_Warning):
    el = 0
    if eth.proto == 8:
        el = 1
        #print(TAB_1 + 'ethproto=8')
        Timeeeee = datetime.datetime.now().strftime('%H%M%S').__str__()
        ipv4 = IPv4(eth.data)
        ipv4src = ipv4.src.__str__()
        ipv4target = ipv4.target.__str__()
        if ipv4.proto == 1:
            icmp = ICMP(ipv4.data)
            icmpinfo = 'Type:'+icmp.type.__str__() +'Code'+ icmp.code.__str__() +'Checksum'+ icmp.checksum.__str__()
            print('{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}'
            .format(count,Timeeeee,ipv4.src, ipv4.target,'ICMP',len(icmp.data),_Warning))
        # TCP
        elif ipv4.proto == 6:
            tcp = TCP(ipv4.data)
            tcpinfo = 'SrcPort:{}, DestPort:{}'.format(tcp.src_port, tcp.dest_port) + ' Sequence:{}, Acknowledgment:{}'.format(tcp.sequence, tcp.acknowledgment) + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh) + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin)
            if(len(tcp.data) > 0 and (tcp.src_port == 80 or tcp.dest_port == 80)):
                print('{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}'   
                .format(count,Timeeeee,ipv4.src, ipv4.target,'HTTP',len(tcp.data),_Warning))
            else:
                print('{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}'
                .format(count,Timeeeee,ipv4.src, ipv4.target,'TCP',len(tcp.data),_Warning))

        # UDP
        elif ipv4.proto == 17:
            udp = UDP(ipv4.data)
            udpinfo = 'SrcPort: {}, DestPort:{}, Length:{}'.format(udp.src_port, udp.dest_port,udp.size)
            print('{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}'
            .format(count,Timeeeee,ipv4.src, ipv4.target,'UDP',len(udp.data),_Warning))
    return el
def checkWarning(_Warning):
    bcolor1 = bColors
    Warningreturn = ''
    if _Warning == 0:
        Warningreturn = ''
    elif _Warning == 1:
        Warningreturn = bcolor1.c_xmasscan +'XMas Scan'+ bcolor1.c_end
    elif _Warning == 2:
        Warningreturn = bcolor1.c_finscan +'Fin Scan'+ bcolor1.c_end
    elif _Warning == 3:
        Warningreturn = bcolor1.c_nullscan +'Null Scan'+ bcolor1.c_end
    elif _Warning == 4:
        Warningreturn = bcolor1.c_pingofdeath  +'Ping of Death'+ bcolor1.c_end
    elif _Warning == 41:
        Warningreturn = bcolor1.c_pingofdeath  +'Ping Active'+ bcolor1.c_end
    elif _Warning == 5:
        Warningreturn = bcolor1.c_landattack +'Land Attack'+ bcolor1.c_end
    elif _Warning == 6:
        Warningreturn = bcolor1.c_finscan +'UDP Scan'+ bcolor1.c_end
    elif _Warning == 9:
        Warningreturn = bcolor1.c_sqlinjection + 'Command Injection' + bcolor1.c_end
    elif _Warning == 91:
        Warningreturn = bcolor1.c_sqlinjection + 'SQL Injection' + bcolor1.c_end
    elif _Warning == 92:
        Warningreturn = bcolor1.c_sqlinjection + 'XSS reflected ' + bcolor1.c_end
    elif _Warning == 93:
        Warningreturn = bcolor1.c_sqlinjection + 'XSS stored' + bcolor1.c_end
    elif _Warning == 99:
        Warningreturn = bcolor1.c_normal +'Connect blackIP'+ bcolor1.c_end
    elif _Warning == 98:
        Warningreturn = bcolor1.c_normal +'Reply blackIP'+ bcolor1.c_end
    return Warningreturn
def checkWarninglog(_Warning):
    bcolor1 = bColors
    Warningreturn = ''
    if _Warning == 0:
        Warningreturn = ''
    elif _Warning == 1:
        Warningreturn ='XMas Scan'
    elif _Warning == 2:
        Warningreturn = 'Fin Scan'
    elif _Warning == 3:
        Warningreturn = 'Null Scan'
    elif _Warning == 4:
        Warningreturn = 'Ping of Death'
    elif _Warning == 41:
        Warningreturn = 'Ping Active'
    elif _Warning == 5:
        Warningreturn = 'Land Scan'
    elif _Warning == 6:
        Warningreturn = 'UDP Scan'
    elif _Warning == 9:
        Warningreturn = 'Command Injection'
    elif _Warning == 91:
        Warningreturn = 'SQL Injection'
    elif _Warning == 92:
        Warningreturn = 'XSS reflected '
    elif _Warning == 93:
        Warningreturn = 'XSS stored'
    elif _Warning == 99:
        Warningreturn = 'Warning blackIP'
    return Warningreturn
def checkSniffer(eth, _listFrameEth):
    _WarningEth = 0
    listblackip1 = blackIP()
    listblackip = listblackip1.readIP()
    if eth.proto == 8:
        ipv4 = IPv4(eth.data)
        ipsource = ipv4.src
        ipdesti = ipv4.target
        proto = ipv4.proto
        _tcpsrc_port = 0
        _tcpdest_port = 0
        _tcplendata = 0
        if ipv4.proto != 6:
            flagfin = 0
            flagsyn = 0
            flagrst = 0
            flagpsh = 0
            flagack = 0
            flagurg = 0
        else:
            tcp = TCP(ipv4.data)
            flagfin = int(tcp.flag_fin)
            flagsyn = int(tcp.flag_syn)
            flagrst = int(tcp.flag_rst)
            flagpsh = int(tcp.flag_psh)
            flagack = int(tcp.flag_ack)
            flagurg = int(tcp.flag_urg)
            _tcpsrc_port = tcp.src_port
            _tcpdest_port = tcp.dest_port
            _tcpldata = tcp.data
        if (ipv4.proto == 6 and _tcpsrc_port == 80 or _tcpdest_port == 80):
            _WarningEth = checkSqlInjection(HTTP(tcp.data)).check
        elif ipsource == ipdesti:
            _WarningEth = checkLandAttack(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn, flagrst, flagpsh, flagack, flagurg).check
        elif (proto == 1):
            icmp = ICMP(ipv4.data)
            _lenicmp = len(icmp.data)
            _WarningEth = checkpingofDead(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn, flagrst, flagpsh, flagack, flagurg, _lenicmp).check
        elif(_WarningEth == 0 and proto == 6):
            if (flagfin == 1 
            and flagurg == 1 
            and flagpsh == 1 
            and proto == 6):
                _WarningEth = checkXmasScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh, flagack, flagurg).check
            elif(flagfin == 1 
            and proto == 6):
                _WarningEth = checkFINScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh, flagack, flagurg).check
            elif(flagfin == 0
            and flagsyn == 0
            and flagrst == 0
            and flagpsh == 0
            and flagack == 0
            and flagurg == 0
            and proto == 6):
                _WarningEth = checkNULLScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh, flagack, flagurg).check
        elif(ipv4.proto ==17 and len(UDP(ipv4.data).data) == 0):
            _WarningEth = checkUDPscan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh, flagack, flagurg).check
        RefeshlistFrame(_listFrameEth, ipsource, ipdesti, proto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
        AddtoFrame(_listFrameEth, ipsource, ipdesti, 1, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
        if(_WarningEth != 0):
            inBlackIP = 0
            for x in range(0,len(listblackip)):
                if ipsource + '\n' == listblackip[x]:
                    inBlackIP = 1
            if (inBlackIP == 0):
                Ip = blackIP()
                Ip.appendIP(ipsource+'\n')
        elif(len(listblackip) > 0 and _WarningEth == 0):
            for x in range(0,len(listblackip)):
                if ipsource + '\n' == listblackip[x]:
                    _WarningEth = 99
                if ipdesti + '\n' == listblackip[x]:
                    _WarningEth = 98
        #printFrame(_listFrameEth)
    return _WarningEth
def checklistAlert(_listAlert, _ip_source, _ip_target, _num_attack):
    if (_num_attack != -1 and _num_attack != 99):
        temp = 0
        for x in _listAlert:
            if (x.ip_source == _ip_source
            and x.ip_target == _ip_target
            and x.num_attack == _num_attack):
                x.time_update = datetime.datetime.now().strftime('%H%M%S')
                x.count_Warning == 0
                temp = 1
        if (temp == 0):
            tempAlert = alertAttack()
            tempAlert.ip_source = _ip_source
            tempAlert.ip_target = _ip_target
            tempAlert.num_attack = _num_attack
            tempAlert.time_start = datetime.datetime.now().strftime('%H%M%S')
            tempAlert.time_finish = "notime"
            tempAlert.time_update = datetime.datetime.now().strftime('%H%M%S')
            tempAlert.count_Warning = 0
            _listAlert.append(tempAlert)
    #print(len(_listAlert))
def RefeshlistAlert(_listAlert):
    if(len(_listAlert) >= 0):
        _list = []
        for x in _listAlert:
            if (x.count_Warning == 0) :
                strlog = x.ip_source +':'+ x.ip_target + ':'+checkWarninglog(x.num_attack).__str__() +':'+'start'+':'+ x.time_start 
                x.count_Warning = 1
                #print('Write file log '+ strlog)
                writeLog("",strlog)
            if (compareTime(x.time_update, datetime.datetime.now().strftime('%H%M%S'))._time > 5):
                x.time_finish = x.time_update 
            if (x.time_finish != "notime"):
                _list.append(x)
                strlog = x.ip_source +':'+ x.ip_target + ':'+checkWarninglog(x.num_attack).__str__() +':'+ 'finish' +':'+ x.time_finish
                #print('Write file log '+ strlog)
                writeLog("",strlog)
                _listAlert.remove((x))
        xft = len(_list)
        #for i in range(0, xft-1):
        #    _listAlert.remove(_listAlert[_list[i]])
def sniffer():
    str = 'capture' + datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
    _count = 1
    _listFrame = []
    _listAlert = []
    pcap = Pcap('Capture/'+str+'.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('\033[91m{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}\n\033[0m'
    .format('No','Time','Source','Destination','Protocol','Length','Info'))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        if (datetime.datetime.now().strftime('%M%S') == '0000'):
            pcap.close()
            str = 'capture' + datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
            pcap = Pcap('Capture/'+str+'.pcap')
        pcap.write(raw_data)
        ethernetdata = Ethernet(raw_data)
        _Warning = checkSniffer(ethernetdata, _listFrame)
        if(_Warning != 0 and _Warning != 99 and _Warning != None and _Warning != 98):
            ipv4 = IPv4(ethernetdata.data)
            _ipsource = ipv4.src
            _iptarget = ipv4.target
            checklistAlert(_listAlert, _ipsource, _iptarget, _Warning)
        RefeshlistAlert(_listAlert)
        _Warningreturn = checkWarning(_Warning)
        if(printSniffer(ethernetdata, _count, _Warningreturn) == 1):
            _count += 1
    pcap.close()
def sendAlert():
    _listAlertmail = []
    _listAlertStack = []
    while True:
        checkLog(_listAlertmail, _listAlertStack)
def main():
    Thread(target=sniffer).start()
    Thread(target=sendAlert).start()
    #sniffer()
if __name__== '__main__':
    main()

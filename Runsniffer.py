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


from Struct.bcolor import bColors
from Struct.frameheader import frameHeader
from Struct.alertattack import alertAttack

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
        print(i.__str__()+'  '+_frameHeader[i].proto.__str__()+ ' ' +_frameHeader[i].flagurg.__str__()+_frameHeader[i].ipsourc.__str__() +' '+_frameHeader[i].ipdesti.__str__()+' '+_frameHeader[i].count.__str__()+' '+_frameHeader[i].time.__str__() + '\n')
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
    if eth.proto == 8:
        #print(TAB_1 + 'ethproto=8')
        ipv4 = IPv4(eth.data)
        ipv4src = ipv4.src.__str__()
        ipv4target = ipv4.target.__str__()
        if ipv4.proto == 1:
            icmp = ICMP(ipv4.data)
            icmpinfo = 'Type:'+icmp.type.__str__() +'Code'+ icmp.code.__str__() +'Checksum'+ icmp.checksum.__str__()
            print('{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}'
            .format(count.__str__(),'Timeeeee',ipv4.src, ipv4.target,'ICMP',len(icmp.data).__str__(),_Warning.__str__()))
        # TCP
        elif ipv4.proto == 6:
            tcp = TCP(ipv4.data)
            tcpinfo = 'SrcPort:{}, DestPort:{}'.format(tcp.src_port, tcp.dest_port) + ' Sequence:{}, Acknowledgment:{}'.format(tcp.sequence, tcp.acknowledgment) + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh) + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin)
            print('{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}'
            .format(count,'Timeeeee',ipv4.src, ipv4.target,'TCP',len(tcp.data),_Warning))       
        # UDP
        elif ipv4.proto == 17:
            udp = UDP(ipv4.data)
            udpinfo = 'SrcPort: {}, DestPort:{}, Length:{}'.format(udp.src_port, udp.dest_port,udp.size)
            print('{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}'
            .format(count,'Timeeeee',ipv4.src, ipv4.target,'UDP',len(udp.data),_Warning))
def checkDosAttack():
    return 0
    return -1
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
    elif _Warning == 5:
        Warningreturn = bcolor1.c_landattack +'Land Attack'+ bcolor1.c_end
    elif _Warning == 99:
        Warningreturn = bcolor1.c_normal +'Warning blackIP'+ bcolor1.c_end
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
    elif _Warning == 5:
        Warningreturn = 'Land Attack'
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
        if ipsource == ipdesti:
            _WarningEth = checkLandAttack(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn, flagrst, flagpsh, flagack, flagurg).check
        elif (proto == 1):
            _WarningEth = checkpingofDead(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn, flagrst, flagpsh, flagack, flagurg).check
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
        RefeshlistFrame(_listFrameEth, ipsource, ipdesti, proto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
        AddtoFrame(_listFrameEth, ipsource, ipdesti, 1,proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
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
        #printFrame(_listFrameEth)
    return _WarningEth
def sniffer_blackIP():
    str = 'capture'+datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
    _count = 1
    _listFrame = []
    pcap = Pcap('Capture/'+str+'.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('\033[91m{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}\n\033[0m'
    .format('No','Time','Source','Destination','Protocol','Length','Info'))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        ethernetdata = Ethernet(raw_data)
        _Warning = checkSniffer(ethernetdata, _listFrame)
        _Warningreturn = checkWarning(_Warning)
        printSniffer(ethernetdata, _count, _Warningreturn)
        _count += 1
    pcap.close()
def checklistAlert(_listAlert, _ip_source, _ip_target, _num_attack):
    if (_num_attack != -1 and _num_attack != 99):
        temp = 0
        for x in range(0,len(_listAlert)):
            if (_listAlert[x].ip_source == _ip_source
            and _listAlert[x].ip_target == _ip_target
            and _listAlert[x].num_attack == _num_attack):
                _listAlert[x].time_update = datetime.datetime.now().strftime('%H%M%S')
                temp = 1
        if (temp == 0):
            tempAlert = alertAttack()
            tempAlert.ip_source = _ip_source
            tempAlert.ip_target = _ip_target
            tempAlert.num_attack = _num_attack
            tempAlert.time_start = datetime.datetime.now().strftime('%H%M%S')
            tempAlert.time_finish = ""
            tempAlert.time_update = datetime.datetime.now().strftime('%H%M%S')
            tempAlert.count_Warning = 0
            _listAlert.append(tempAlert)
            content = 'Attack ' + checkWarninglog(_num_attack) + ' from:'+ _ip_source + ' to:' + _ip_target + datetime.datetime.now().strftime('%H%M%S')
            subject = 'System Warning'
            try:
                send_message(content, subject)
                print("Send Alert Mail Success")
            except:
                print("Send Alert Mail Fail") 
def RefeshlistAlert(_listAlert):
    if(len(_listAlert) != 0):
        _list = []
        for x in range(0,len(_listAlert)):
            if (_listAlert[x].time_finish != ""):
                _list.append(x)
                strlog = _listAlert[x].ip_source +':'+ _listAlert[x].ip_target + ':'+checkWarninglog(_listAlert[x].num_attack).__str__() +':'+ _listAlert[x].time_start +':'+ _listAlert[x].time_finish
                print('Write file log '+ strlog)
                writeLog("",strlog)
            if (compareTime(_listAlert[x].time_update, datetime.datetime.now().strftime('%H%M%S'))._time > 5):
                _listAlert[x].time_finish = _listAlert[x].time_update 
        xft = len(_list)
        for i in range(0, xft):
            _listAlert.remove(_listAlert[_list[i]])

def sniffer():
    str = 'capture'+datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
    _count = 1
    _listFrame = []
    _listAlert = []
    pcap = Pcap('Capture/'+str+'.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('\033[91m{0:5}\t{1:8}\t{2:15}\t\t{3:15}\t\t{4:8}\t{5:6}\t\t{6}\n\033[0m'
    .format('No','Time','Source','Destination','Protocol','Length','Info'))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        ethernetdata = Ethernet(raw_data)
        _Warning = checkSniffer(ethernetdata, _listFrame)
        if(_Warning != 0 and _Warning != 99 and _Warning != None):
            ipv4 = IPv4(ethernetdata.data)
            _ipsource = ipv4.src
            _iptarget = ipv4.target
            checklistAlert(_listAlert, _ipsource, _iptarget, _Warning)
        RefeshlistAlert(_listAlert)
        _Warningreturn = checkWarning(_Warning)
        printSniffer(ethernetdata, _count, _Warningreturn)
        _count += 1
    pcap.close()
def main():
    sniffer()
if __name__== '__main__':
    main()

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
from Alert.sendmail import Sendmail

from Detection.checkxmasscan import checkXmasScan
from Detection.checkfinscan import checkFINScan
from Detection.checknullscan import checkNULLScan
from Detection.checkpingofdead import checkpingofDead
from Detection.comparetime import compareTime

import sys

TAB_1 = '\t - '
DATA_TAB_2 = '\t\t '

class frameHeader:
    ipsourc = str()
    ipdesti = str()
    time = str()
    count = int()
    proto = str()
    flagfin = int()
    flagsyn = int()
    flagrst = int()
    flagpsh = int()
    flagack = int()
    flagurg = int()
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
def RefreshlistFrameTime(_listFrame):
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
def RefreshlistFrame(_listFrame, ipsource, ipdesti, proto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
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
        # Other IPv4
        else:
            print(TAB_1 + 'Other IPv4 Data:')
            print(format_multi_line(DATA_TAB_2, ipv4.data))

    else:
        print('Ethernet Data: = Protocol != 8  {}'.format(eth.proto))
def checkDosAttack():
    return 0
    return -1
def checkWarning(_Warning):
    Warningreturn = 'No Problem'
    if _Warning == 0:
        Warningreturn = '\033[1mNo Problem\033[0m'
    elif _Warning == 1:
        Warningreturn = '\033[92mXMas Scan\033[0m'
    elif _Warning == 2:
        Warningreturn = '\033[93mFin Scan\033[0m'
    elif _Warning == 3:
        Warningreturn = '\033[94mNull Scan\033[0m'
    elif _Warning == 4:
        Warningreturn = '\033[91mPing of Death\033[0m'
    elif _Warning == 5:
        Warningreturn = '\033[107mDos Attack - Land Attack\033[0m'
    return Warningreturn
def checkSniffer(eth,_listFrameEth):
    _WarningEth = 0
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
        if (proto == 1):
            _WarningEth = checkpingofDead(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn, flagrst, flagpsh, flagack, flagurg).check
        if(_WarningEth == 0 and proto == 6):
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
        RefreshlistFrame(_listFrameEth, ipsource, ipdesti, proto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
        AddtoFrame(_listFrameEth, ipsource, ipdesti, 1,proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
        #printFrame(_listFrameEth)
        return _WarningEth
def sniffer():
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
def main():
    sniffer()
if __name__== '__main__':
    main()

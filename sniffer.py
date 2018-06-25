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

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '
sourceIpv4 = {''}

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
    for i in range(0,len(_frameHeader)-1):
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
def searchIPsrclist(_frameHeader,ipsource):
    listSIP = []
    for x in range(0,len(_frameHeader)):
        if (ipsource == _frameHeader[x].ipsourc):
            listSIP.append(x)
    return listSIP
def searchIPsrc(_frameHeader,ipsource):
    for x in range(0,len(_frameHeader)):
        if (ipsource == _frameHeader[x].ipsourc):
            return x
    return -1
def AddtoFrame(_frameHeader, ipsource, ipdesti, count, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg ):
    if (searchforframe(_frameHeader, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg) == -1):
        Frame = frameHeader()
        Frame.ipsourc = ipsource
        Frame.ipdesti = ipdesti
        Frame.time = datetime.datetime.now().strftime("%H%M%S")
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
        _frameHeader[searchforframe(_frameHeader, ipsource, ipdesti, proto, flagfin, 
            flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)].count += 1
        _frameHeader[searchforframe(_frameHeader, ipsource, ipdesti, proto, flagfin, 
            flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)].time == datetime.datetime.now().strftime("%H%M%S")
def printFrame(_frameHeader):
    for i in range(0,len(_frameHeader)):
        print(_frameHeader[i].ipsourc.__str__() +" "+_frameHeader[i].ipdesti.__str__()+" "+_frameHeader[i].count.__str__())
def count():
    print('hala')
#Xuat data Ethernet
def compareTime(timeStart, timeFinish):
    _timeStart = int(timeStart[0:2])*3600 + int(timeStart[2:4]) + int(timeStart[4:6])
    _timeFinish = int(timeFinish[0:2])*3600 + int(timeFinish[2:4]) + int(timeFinish[4:6])
    if (_timeFinish < _timeStart):
        return ((_timeFinish + 86400) - _timeStart)
    else:
        return (_timeFinish  - _timeStart)
def RefreshlistFrame(_listFrame, ipsource, ipdesti, proto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
    if (searchforframe(_listFrame, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg) != -1):
        _listFrame[searchforframe(_listFrame, ipsource, ipdesti, proto,
        flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)].count +=1
    listF = []
    for i in range(0,len(_listFrame)-1):
        if (compareTime(datetime.datetime.now().strftime("%H%M%S"), _listFrame[i].time) > 10):
            if (_listFrame[i].count == 1):
                listF.append(i)
            else:
                _listFrame[i].count -= 1
    for x in range(len(listF),0):
        if (compareTime(datetime.datetime.now().strftime("%H%M%S"), _listFrame[x].time) > 10):
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
            print('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t{6}'.format(count.__str__(),"Timeeeee",ipv4.src, ipv4.target,'ICMP',len(icmp.data).__str__(),_Warning.__str__()))
        # TCP
        elif ipv4.proto == 6:
            tcp = TCP(ipv4.data)
            tcpinfo = 'SrcPort:{}, DestPort:{}'.format(tcp.src_port, tcp.dest_port) + ' Sequence:{}, Acknowledgment:{}'.format(tcp.sequence, tcp.acknowledgment) + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh) + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin)
            '''
            if len(tcp.data) > 0:
            
                #HTTP
                if tcp.src_port == 80 or tcp.dest_port == 80:
                    print(TAB_2 + 'HTTP Data:')
                    try:
                        http = HTTP(tcp.data)
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            print(DATA_TAB_3 + str(line))
                    except:
                        print(format_multi_line(DATA_TAB_3, tcp.data))
                else:
                    print(TAB_2 + 'TCP Data:')
                    #print(format_multi_line(DATA_TAB_3, tcp.data))
            '''
            print('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t{6}'.format(count,'Timeeeee',ipv4.src, ipv4.target,'TCP',len(tcp.data),_Warning))       
        # UDP
        elif ipv4.proto == 17:
            #print(TAB_1 + 'ethproto=17')
            udp = UDP(ipv4.data)
            udpinfo = 'SrcPort: {}, DestPort:{}, Length'.format(udp.src_port, udp.dest_port,udp.size)
            #print(TAB_1 + 'UDP Segment:')
            #print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port,udp.size))
            print('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t{6}'.format(count,"Timeeeee",ipv4.src, ipv4.target,'UDP',len(udp.data),_Warning))
        # Other IPv4
        else:
            print(TAB_1 + 'Other IPv4 Data:')
            print(format_multi_line(DATA_TAB_2, ipv4.data))

    else:
        print('Ethernet Data: = Protocol != 8  {}'.format(eth.proto))
        # print(format_multi_line(DATA_TAB_1, eth.data))
#Luu du lieu data_raw vao pcap
def checkXmasScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):   
    if (searchIPsrc(_listFrameEth,ipsource)) == -1:
        return 0
    elif (_listFrameEth[searchIPsrc(_listFrameEth,ipsource)].ipsourc == ipsource
    and _listFrameEth[searchIPsrc(_listFrameEth,ipsource)].flagfin == 1 
    and _listFrameEth[searchIPsrc(_listFrameEth,ipsource)].flagurg == 1 
    and _listFrameEth[searchIPsrc(_listFrameEth,ipsource)].flagpsh ==1
    and _listFrameEth[searchIPsrc(_listFrameEth,ipsource)].flagsyn == 0
    and _listFrameEth[searchIPsrc(_listFrameEth,ipsource)].flagrst == 0 
    and _listFrameEth[searchIPsrc(_listFrameEth,ipsource)].flagack == 0
    and _listFrameEth[searchIPsrc(_listFrameEth,ipsource)].count >= 4):
        return 1
    else:
        listXmax = 0
        for x in range(0,len(_listFrameEth)):
            if (_listFrameEth[x].ipsourc == ipsource
            and _listFrameEth[x].flagfin == 1 
            and _listFrameEth[x].flagurg == 1 
            and _listFrameEth[x].flagpsh == 1):
                listXmax += 1
        if listXmax >= 5:
            return 1
    return 1
def checkFINScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg): 
    if(flagsyn == 1
    or flagrst == 1
    or flagpsh == 1
    or flagack == 1
    or flagurg == 1):
        return 0
    else:
        indexIP = searchIPsrclist(_listFrameEth, ipsource)
        if (len(indexIP) != 0):
            xft = len(indexIP)
            for x in range(0,xft-1):
                if (_listFrameEth[indexIP[x]].ipsourc == ipsource
                and _listFrameEth[indexIP[x]].flagfin == 1 
                and _listFrameEth[indexIP[x]].flagurg == 0 
                and _listFrameEth[indexIP[x]].flagpsh == 0
                and _listFrameEth[indexIP[x]].flagsyn == 0
                and _listFrameEth[indexIP[x]].flagrst == 0 
                and _listFrameEth[indexIP[x]].flagack == 0
                and _listFrameEth[indexIP[x]].count >= 5): 
                    return 2
        else:
            listFinScan = 0
            for x in range(0,len(_listFrameEth)-1):
                if (_listFrameEth[x].ipsourc == ipsource 
                and _listFrameEth[x].flagfin == 1):
                    listFinScan += 1
            if listFinScan >= 4:
                return 2
    return 0
def checkNULLScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
    indexIP = searchIPsrclist(_listFrameEth, ipsource)
    if (len(indexIP) != 0):
        xft = len(indexIP)
        for x in range(0,xft-1):
            if (_listFrameEth[indexIP[x]].ipsourc == ipsource
            and _listFrameEth[indexIP[x]].flagfin == 0 
            and _listFrameEth[indexIP[x]].flagurg == 0 
            and _listFrameEth[indexIP[x]].flagpsh == 0
            and _listFrameEth[indexIP[x]].flagsyn == 0
            and _listFrameEth[indexIP[x]].flagrst == 0 
            and _listFrameEth[indexIP[x]].flagack == 0
            and _listFrameEth[indexIP[x]].count >= 5): 
                return 3
    else:
        listNullScan = 0
        for x in range(0,len(_listFrameEth)):
            if (_listFrameEth[x].ipsourc == ipsource 
            and _listFrameEth[x].flagfin == 1):
                listNullScan += 1
        if listNullScan >= 10:
            return 3
    return 0
def checkPingofDeath(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg):
    _WarningEth = 0
    index = searchforframe(_listFrameEth, ipsource, ipdesti, proto, flagfin,flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
    if index != -1:
        if _listFrameEth[index].count >= 1000:
            _WarningEth = 4
        else:
            _WarningEth = 0
    return _WarningEth
def checkDosAttack():
    return -1
def checkWarning(_Warning):
    Warningreturn = "No Problem"
    if _Warning == 0:
        Warningreturn = "No Problem"
    elif _Warning == 1:
        Warningreturn = "XMas Scan"
    elif _Warning == 2:
        Warningreturn = "Fin Scan"
    elif _Warning == 3:
        Warningreturn = "Null Scan"
    elif _Warning == 4:
        Warningreturn = "Ping of Death"
    elif _Warning == 5:
        Warningreturn = "Dos Attack - Land Attack"
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
        _WarningEth = checkPingofDeath(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn, flagrst, flagpsh, flagack, flagurg)
        if(_WarningEth == 0):
            if (flagfin == 1 
            and flagurg == 1 
            and flagpsh == 1 
            and proto == 6):
                _WarningEth = checkXmasScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh, flagack, flagurg)
            elif(flagfin == 1 
            and proto == 6):
                _WarningEth = checkFINScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh, flagack, flagurg)
            elif(flagfin == 0
            and flagsyn == 0
            and flagrst == 0
            and flagpsh == 0
            and flagack == 0
            and flagurg == 0
            and proto == 6):
                _WarningEth = checkNULLScan(_listFrameEth, ipsource, ipdesti, proto, flagfin, flagsyn ,flagrst ,flagpsh, flagack, flagurg)
        #printFrame(_listFrameEth)
        RefreshlistFrame(_listFrameEth, ipsource, ipdesti, proto,flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
        #print("Sau khi refresh")
        #printFrame(_listFrameEth)
        AddtoFrame(_listFrameEth, ipsource, ipdesti, 1,proto, flagfin, flagsyn ,flagrst ,flagpsh ,flagack ,flagurg)
        return _WarningEth
def sniffer():
    str = 'capture'+datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
    pcap = Pcap('Capture/'+str+'.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t{6}'.format('No','Time','Source','Destination','Protocol','Length','Info'))
    _count = 1
    _listFrame = []
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

main()

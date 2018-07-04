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
x = '0929235126'
y = 'Thien tai la dung ne'
 
Sending(y,x)

 
#Sending(y,x)
'''
def Sending(message, sender):
    cmd1 = '/dev/ttyUSB3'
    cmd2 = 'AT+CMGF=1\r'
    cmd3 = 'AT+CMGS='+sender+'\r\n'
    cmd4 = message+'\x1A'
    try:
        SerialPort = serial.Serial(cmd1,19200)
        SerialPort.write(cmd2.encode('utf-8'))
        time.sleep(1)
        SerialPort.write(cmd3.encode())
        time.sleep(1)
        SerialPort.write(cmd4.encode())
        time.sleep(1)
        print ('Bat dau gui tin, hay kt so dien thoai duoc gui')
        SerialPort.close()
    except:
        print('Gui goi tin that bai')
Sending('Thien tai la anh','0929235126')
'''
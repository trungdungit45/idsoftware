import serial
import time
def Sending(message, sender):
    cmd1 = '/dev/ttyUSB4'
    cmd2 = 'AT+CMGF=1\r'
    cmd3 = 'AT+CMGS="'+sender+'"\r\n'
    cmd4 = message+"\x1A"
    SerialPort = serial.Serial(cmd1,19200)

    SerialPort.write(cmd2.encode('utf-8'))
    time.sleep(1)
    SerialPort.write(cmd3.encode())
    time.sleep(1)
    SerialPort.write(cmd4.encode())
    time.sleep(1)
    print ('Bat dau gui tin, hay kt so dien thoai duoc gui')
    SerialPort.close()
Sending("Thien tai la anh","0929235126")
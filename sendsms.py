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
    print ('Send SMS Success')
    SerialPort.close()
def sendSMS(message, sender):
    Sending(message,sender)
    
#sender = '01652582138'
#message = 'System Warning'
#sendSMS(message, sender)


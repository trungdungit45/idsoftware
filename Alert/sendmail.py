import email
import imaplib
import ctypes
import smtplib
import getpass
import re
import base64
import string
import sys
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

class Sendmail:
    def __init__(self, content, subject):
        try:
            send_message(content, subject)
            print("Send Alert Mail Success")
        except:
            print("Send Alert mail Fail")     
    def send_message(content, subject):
        my_email = 'idssoftwaremonitor@gmail.com'
        password_my_email = 'idssoftware123'
        to_email = 'kenteavip@gmail.com'
        session_out = smtplib.SMTP('smtp.gmail.com', 587)      
        session_out.ehlo()
        session_out.starttls()
        session_out.ehlo
        session_out.login(mail.my_email, mail.password_my_email)
        msg = MIMEMultipart()
        msg['From'] = mail.my_email
        msg['To'] = mail.to_email
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        msg.attach(MIMEText(content))
        session_out.sendmail(mail.my_email, mail.to_email, msg.as_string())
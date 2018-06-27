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

class Gmail:
    server_outgoing = 'smtp.gmail.com'
    server_incoming = 'imap.gmail.com'
    port_outgoing_tls = 587
    port_incoming_ssl = 993
    my_email = 'idssoftwaremonitor@gmail.com'
    password_my_email = 'idssoftware123'
    subject = ''
    content = ''
    to_email = 'kltn27062018@gmail.com'
def decode_base64(selft, data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'=' * (4 - missing_padding)
    return base64.decodestring(data)
def send_message( content, subject):
    mail = Gmail()
    session_out = smtplib.SMTP(mail.server_outgoing, mail.port_outgoing_tls)
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

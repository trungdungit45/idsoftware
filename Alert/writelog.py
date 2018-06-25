import logging
import datetime
import sys
class Writelog:
	def __init__(self, info, warn):  
		str = ':'+datetime.datetime.now().strftime('%d:%m:%Y:%H:%M:%S')
		logging.basicConfig(filename='Log/snifflog.log', level=logging.INFO)
		if (info == ""):
			logging.warning(warn+str)
		else:
			logging.info(info+str)

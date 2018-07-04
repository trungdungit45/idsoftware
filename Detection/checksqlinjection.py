class checkSqlInjection():
	"""docstring for ClassName"""
	def __init__(self, _httpdata):
		self.check = 0
		sql_injec = 0
		http_info = str(_httpdata.data).split('\n')
		for line in http_info:
			if ('union' in str(line)):
				sql_injec = 1
			if(sql_injec == 1):
				self.check = 9                
	
class checkSqlInjection():
	"""docstring for ClassName"""
	def __init__(self, _httpdata):
		self.check = 0
		sql_injec = 0
		http_info = str(_httpdata.data).split('\n')
		for line in http_info:
			if ('cat /etc/passwd' in str(line) or 'index.php | pwd' in str(line) or 'exec || ls' in str(line) or 'exec & ifconfig' in str(line) or 'pwd' in str(line)):
				sql_injec = 2
			if('union' in str(line) or 'order by' in str(line)):
				sql_injec = 1
			if('<script>alert(document.cookie)</script>' in str(line) or '<svg onload=prompt(document.cookie)>' in str(line)):
				sql_injec = 3
			if('<script>alert' in str(line) or '<script lenguaje' in str(line)):
				sql_injec = 4
			if(sql_injec == 1):
				self.check = 9
			if(sql_injec == 2):
				self.check = 91
			if(sql_injec == 3):
				self.check = 92
			if(sql_injec == 4):
				self.check = 93

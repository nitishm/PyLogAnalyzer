import logging
'''
Class for logging
'''


class Logger:
	def __init__(self, name, level):
		self.logger = logging.getLogger()
		self.logger.setLevel(logging.DEBUG)
		self.fh = logging.FileHandler(name + ".log")
		self.fh.setLevel(logging.DEBUG)
		self.ch = logging.StreamHandler()
		self.ch.setLevel(logging.ERROR)
		self.formatter = logging.Formatter('%(levelname)s:%(asctime)s - %(message)s')

		self.fh.setFormatter(self.formatter)
		self.ch.setFormatter(self.formatter)
		
		self.logger.addHandler(self.fh)
		self.logger.addHandler(self.ch)

		self.level = level
		self.set_log_level()

	def set_log_level(self):
		if self.level is "debug":
			logging.root.setLevel(logging.DEBUG)
		elif self.level is "info":
			logging.root.setLevel(logging.INFO)

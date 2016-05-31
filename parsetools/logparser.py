from collections import defaultdict
from datetime import datetime
import multiprocessing as mp
import operator
import time
from pyparsing import *
from grammar.grammar import Grammar
from logtools.logger import Logger
from pcaptools.pcapparser import PcapGen
'''
Class for parsing lines based on defined grammar.
Grammar is defined in the __init__ function
'''


MAX_CORES = 32
MAX_OCTS = 2
class Parser(object):
	def __init__(self, filename):
		'''
		Initialise the grammar to be used to parse each line in the log file
		Setup multiprocessing shared object and other generic structs
		'''
		#Function dictionary, something to mimic function pointers
		self.parse_line = {
			'octeon':self.parse_line_octeon,
			'others':self.parse_line_other
		}

		self.log = Logger("parser","info") #???? Not the nest implementation yet
		#Initialise variables
		self.__filepath = filename
		#Setup the grammar to use based on the filetype
		self.__grammar_type = self.get_grammar_type(filename)
		self.__current_grammar = Grammar(self.__grammar_type).grammar

		self.parse_file()

	def parse_file(self):
		'''
		Read a file and distribute chunks to parsing routine.
		Collect chunks and send for generating the final parsed
		list.
		'''
		self.__manager = mp.Manager()
		self.__out_list = self.__manager.list()
		self.__dict_list,self.__lines, self.__pcap_text = [],[],[]
		self.__last_ppm_timestamp = [[(-1,0)]*MAX_CORES]*MAX_OCTS
		with open(self.__filepath,'r') as f:
			self.__lines = f.readlines()
			self.__num_lines = len(self.__lines)
			self.__chunk_size = self.__num_lines/mp.cpu_count()
			self.__chunk_size = self.__num_lines \
				if self.__chunk_size < self.__num_lines \
				else self.__chunk_size
			#Distribute work to processes in chunks
			processes = [mp.Process(target=self.parse_line[self.__grammar_type], args=(index,))\
				for index in range(0,len(self.__lines),self.__chunk_size)]
			[process.start() for process in processes]
			[process.join() for process in processes]
		#Cleanup parsed object list
		self.generate_parsed_list()

	def parse_line_octeon(self, index):
		'''
		Parse a chunk of lines from original file to create
		a list of defaultdict objects, which is appended to 
		a multiprocessing Queue as a tuple (starting index,list(defaultdict))
		'''
		temp_list = []
		for offset,line in enumerate(self.__lines[index:]):
			lineno = index + offset
			self.log.logger.debug("[File:%s]Parsing:[line#%d]%s" \
				% (self.__filepath,lineno,line.strip()))
			try:
				result = self.__current_grammar.parseString(line)
			except ParseException:
				self.log.logger.error("[File:%s]Unrecognized format:[line#%d]%s" \
					% (self.__filepath,lineno,line.strip()))
				return
			
			if not result.core:
				self.log.logger.error("[File:%s]Expected [core#] field:[line#%d]%s" \
					% (self.__filepath,lineno,line.strip()))
				return

			if not (result.linux or result.vxworks):
				self.log.logger.error("[File:%s]Not a linux or vxworks format:[line#%d]%s" \
					% (self.__filepath,lineno,line.strip()))
				return

			dic = defaultdict(int)
			dic["systime"] = datetime.strptime(" ".join(result.systime),"%b %d %H:%M:%S.%f")			
			if result.timestamp or result.ppm:
				if result.linux:
					dic['oct'], dic['core'], dic['ppm'], dic['timestamp'] = \
						result.octeon, result.core, result.ppm, result.timestamp
				else:
					dic['oct'] = 0
					dic['core'], dic['ppm'], dic['timestamp'] = \
						result.core, result.ppm, result.timestamp
			else:
				if result.linux:
					dic['oct'], dic['core'] = result.octeon,result.core
				else:
					dic['oct'] = 0
					dic['core'] = result.core
				dic['ppm'] = -1
				dic['timestamp'] = -1
			dic['p_pcap'] = "".join(result.pcap)
			dic['p_line'] = lineno
			temp_list.append(dict(dic))
		self.__out_list.append((index,temp_list))

	def parse_line_other(self, index):
		'''
		Parse a chunk of lines from original file to create
		a list of defaultdict objects, which is appended to 
		a multiprocessing Queue as a tuple (starting index,list(defaultdict))
		'''
		temp_list = []
		for offset,line in enumerate(self.__lines[index:]):
			lineno = index + offset
			self.log.logger.debug("[File:%s]Parsing:[line#%d]%s" \
				% (self.__filepath,lineno,line.strip()))
			try:
				result = self.__current_grammar.parseString(line)
			except ParseException:
				self.log.logger.error("[File:%s]Unrecognized format:[line#%d]%s" \
					% (self.__filepath,lineno,line.strip()))
				return
			
			dic = defaultdict(int)
			dic['systime'] = datetime.strptime(" ".join(result.systime),"%b %d %H:%M:%S.%f")			
			dic['p_line'] = lineno
			temp_list.append(dict(dic))
		self.__out_list.append((index,temp_list))

	def generate_parsed_list(self):
		'''
		Sort based on index from return tuple list and flatten the list of dicts
		Update the timestamp and ppm field of the dicts by using last known ts and ppm
		for given oct/core values.
		'''
		self.__dict_list = sorted(self.__out_list,key=lambda x: x[0])
		self.__dict_list = [item for tup in self.__dict_list for item in tup[1]]
		for item in iter(self.__dict_list):
			item['systime'] = item['systime'].replace(year=datetime.now().year)
			if self.__grammar_type == "octeon":
				if item['timestamp'] > 0 or item['ppm'] > 0:
					self.__last_ppm_timestamp[item['oct']][item['core']] = (item['ppm'],item['timestamp'])
				else:
					item['ppm'],item['timestamp'] = self.__last_ppm_timestamp[item['oct']][item['core']]
				self.__pcap_text.append(item['p_pcap'])

	def get_grammar_type(self,filename):
		if set("log.octData").issubset(set(self.__filepath)):
			return "octeon"
		else:
			return "others"

	def get_pcap_text(self):
		return self.__pcap_text

	def get_filename(self):
		'''Return the file from which the object was created'''
		return self.__filepath

	def get_lines(self):
		'''Return a list of lines from the original file'''
		return self.__lines

	def get_len(self):
		'''Return length of list of lines from the original file'''
		return self.__num_lines

	def get_dict_list(self):
		'''
		Return a list of defaultdict objects created on parsing
		lines from the original file
		''' 
		return self.__dict_list

	def get_sortable_attributes(self):
		'''Return a list of current keys in the dict list'''
		attributes = [key for key in self.__dict_list[0].keys() if not str(key).startswith('p_')]
		return attributes

	def print_sorted_list(self,attr):
		for item in sorted(self.__dict_list, key=operator.itemgetter(attr)):
			print self.__lines[item["p_line"]].strip()


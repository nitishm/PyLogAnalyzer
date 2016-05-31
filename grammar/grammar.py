from pyparsing import *
'''
Class to define your grammar object
'''


class Grammar(object):
	def __init__(self,grammar_type):
		self.init_grammar(grammar_type)

	def init_grammar(self, grammar_type):
		self.init_generic_grammar()
		if grammar_type == "octeon":
			self.grammar = self.init_octeon_grammar()
		else:
			self.grammar = self.__date("systime")

	def init_generic_grammar(self):
		'''
		Generic Grammar:
		nums::			'0'...'9'
		num:: 			(nums+)
		words:: 		[a-z][A-Z]
		word:: 			(words+)
		open brace::	"["
		close brace:: 	"]"
		colon:: 		':'
		sys time:: 		((num) + colon)+ '.' + (num)
		date::			(word) + (num) + (time)
		'''
		self.__num = Word(nums)
		self.__word = Word(alphas)
		self.__open_brace = Suppress(Literal("["))
		self.__close_brace = Suppress(Literal("]"))
		self.__colon = Literal(":")
		self.__sys_ts = Regex(r"\d\d:\d\d:\d\d\.\d\d\d")		
		self.__date = self.__word + self.__num + self.__sys_ts

	def init_octeon_grammar(self):
		'''
		Octeon Grammar
		is cavium:: 	(open brace) + (word) + (close brace)
		is vxworks:: 	(open brace) + (num) + (close brace)

		oct id:: 		(open brace) + (word) + ("=") + (num) + (close brace)
		core id:: 		(open brace) + (word) + ("#") + (num) + (close brace)
		ppm id:: 		(open brace) + (num) + (close brace)
		oct timestamp:: (open brace) + (num) + (close brace)
		hexnum::        (hexnums+)
		pcap dump::     (hexnum +(":")) + (hexnum)+
		tags:: 			(date) + (is cavium|is vxworks)? + (oct id)? + (core id) + (ppm id)? + (oct timestamp)? + (pcap dump)?
		'''
		self.__is_linux = self.__open_brace + self.__word + self.__close_brace
		self.__is_vxworks = self.__open_brace + self.__num + self.__close_brace
		self.__oct_id = self.__open_brace + Suppress(self.__word) + Suppress(Literal("=")) \
				+ self.__num + self.__close_brace
		self.__core_id = self.__open_brace + Suppress(self.__word) + Suppress(Literal("#")) \
				+ self.__num + self.__close_brace
		self.__ppm_id = self.__open_brace + self.__num + self.__close_brace
		self.__oct_ts = self.__open_brace + self.__num + self.__close_brace
		self.__pcap = Suppress(Word(hexnums) + Literal(":")) + OneOrMore(Word(hexnums))
		grammar = \
				self.__date("systime") \
				+ Optional(self.__is_linux("linux")|self.__is_vxworks("vxworks")) \
				+ Optional(self.__oct_id("octeon")	.setParseAction(lambda toks:int(toks[0]))) \
		 		+ self.__core_id("core")			.setParseAction(lambda toks:int(toks[0])) \
		 		+ Optional(self.__ppm_id("ppm")		.setParseAction(lambda toks:int(toks[0])) \
		 		+ self.__oct_ts("timestamp")		.setParseAction(lambda toks:int(toks[0]))) \
		 		+ Optional(self.__pcap("pcap"))
		return grammar


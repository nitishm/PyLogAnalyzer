import sys
from parsetools.logparser import Parser
from pcaptools.pcapparser import PcapGen
if __name__ == '__main__':
	p = Parser(sys.argv[1])
	p.print_sorted_list(sys.argv[2])
	print p.get_sortable_attributes()
	pc = PcapGen(p,"output.txt")
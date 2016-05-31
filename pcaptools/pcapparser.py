import string
from logtools.logger import *
'''
Class for converting hexdumps to text2pcap readable format
'''


class PcapGen:
    def __init__(self,parser,filepath):
        self.__to_filename = filepath
        self.__log = Logger("pcap","error")
        self.__parser = parser
        self.__from_filename = self.__parser.get_filename()
        self.__pcap_text = parser.get_pcap_text()
        self.generate_pcap_from_list()

    def write_string_to_pcap(self, hexstring, openfile):
        list_bytes = [hexstring[byte:byte+2] for byte in range(0, len(hexstring), 2)]
        list_octets = [list_bytes[i:i+16] for i in range(0, len(list_bytes), 16)]
        count = 0
        for octet in list_octets:
            pcapline = ("%08x" % (count)) + ": " + " ".join(octet) + "\n"
            count += 16
            openfile.write(pcapline)

    def generate_pcap_from_list(self):
        with open(self.__to_filename,"w") as openfile:
            self.list_of_hexstrings = []
            hexstring = ""
            for line in self.__pcap_text:
                if line:
                    hexstring += line
                else:
                    if hexstring:
                        self.list_of_hexstrings.append(hexstring)
                        hexstring = ""
            for count,hexstring in enumerate(self.list_of_hexstrings):
                self.write_string_to_pcap(hexstring,openfile)
            self.__log.logger.info("[File:%s]Successfully wrote %d packets to file %s" \
                % (self.__from_filename, count+1, self.__to_filename))

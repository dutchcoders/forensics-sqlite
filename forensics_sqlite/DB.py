import struct
import sys

class DB():
	# http://sqlite.org/fileformat2.html
	def __init__(self, f):
		self.f = f

		HEADER = ">16sHBB"
		size = struct.calcsize(HEADER)
		data = self.f.read(size)
		(self.signature, self.page_size, self.write_version, self.read_version) = (struct.unpack(HEADER,data))
		pass

	def process(self):
		pass	
				

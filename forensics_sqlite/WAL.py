import struct
import sys

class WAL():
	# http://www.cclgroupltd.com/the-forensic-implications-of-sqlites-write-ahead-log/
	def __init__(self, f):
		self.f=f

		HEADER = ">LLLLLLLL"
		size = struct.calcsize(HEADER)
		data = self.f.read(size)
		(self.signature, self.version, self.page_size, self.sequence, self.salt1, self.salt2, self.checksum1, self.checksum2) = (struct.unpack(HEADER,data))
		if not (self.signature==0x377F0682 or self.signature==0x377F0683):
			raise Exception("Invalid signature ({:02x})".format(self.signature))
		pass

	def frames(self):
		while True:
			FRAME = ">LLLLLL"
			size = struct.calcsize(FRAME)
			data = self.f.read(size)
			if (len(data)) == 0:
				break

			(page_number, size_in_pages, salt1, salt2, checksum1, checksum2) = (struct.unpack(FRAME,data))
			page = self.f.read(self.page_size)
			yield (page_number, size_in_pages, salt1, salt2, checksum1, checksum2, page)
			

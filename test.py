import struct
import sys
from forensics_sqlite import DB, WAL

"""
-wal write-ahead-log
-shm wal-index (shared memory)
"""
		
if __name__ == '__main__':
	with open("{0}-wal".format(sys.argv[1]), 'r') as f:
		wal = WAL(f)

		print ("Version {:02x}".format(wal.version))
		print ("Page size {:02x}".format(wal.page_size))
		print ("Sequence {:02x}".format(wal.sequence))
		print ("Salt1 {:02x}".format(wal.salt1))
		print ("Salt2 {:02x}".format(wal.salt2))
		print ("Checksum1 {:02x}".format(wal.checksum1))
		print ("Checksum2 {:02x}".format(wal.checksum2))

		for (page_number, size_in_pages, salt1, salt2, checksum1, checksum2, page) in wal.frames():
			print ("Current position {0}".format(f.tell()))
			print ("Page number {:02x}".format(page_number))
			if size_in_pages>0:
				print ("Commit: Size in pages {:02x}".format(size_in_pages))
			print ("Salt1 {:02x}".format(salt1))
			print ("Salt2 {:02x}".format(salt2))
			print ("Checksum1 {:02x}".format(checksum1))
			print ("Checksum2 {:02x}".format(checksum2))
			print (page)


	with open(sys.argv[1], 'r') as f:
		db = DB(f)
		version = { 1: "Legacy", 2: "WAL" }
		print ("{0} {1} {2} {3}".format(db.signature, db.page_size, version[db.write_version], version[db.read_version]))
		pass #main (f)
		

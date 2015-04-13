import zlib
import hashlib
import os

# Hash/verification functions; perform operation on specific file
# CRC32
def crc32hash(filepath, blocksize=16 * 1024 * 1024):
	seed = 0
	with open(filepath, 'rb') as f:
		for chunk in iter(lambda: f.read(1024), b''):
			seed = zlib.crc32(chunk, seed)
	final = format(seed & 0xFFFFFFFF, "x")
	return final

# Adler32
def adler32hash(filepath, blocksize=16 * 1024 * 1024):
	asum = 1
	with open(filepath, 'rb') as f:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			asum = zlib.adler32(data, asum)
			if asum < 0:
				asum += 2**32
	final = format(asum & 0xFFFFFFFF, "x")
	return final

# SHA-1
def sha1hash(filepath, blocksize=16 * 1024 * 1024):
	sha1 = hashlib.sha1()
	f = open(filepath, 'rb')
	try:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			sha1.update(data)  # read in 16MB chunks, not whole autoloader
	finally:
		f.close()
	return sha1.hexdigest()

# SHA-224
def sha224hash(filepath, blocksize=16 * 1024 * 1024):
	sha224 = hashlib.sha224()
	f = open(filepath, 'rb')
	try:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			sha224.update(data)  # read in 16MB chunks, not whole autoloader
	finally:
		f.close()
	return sha224.hexdigest()

# SHA-256
def sha256hash(filepath, blocksize=16 * 1024 * 1024):
	sha256 = hashlib.sha256()
	f = open(filepath, 'rb')
	try:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			sha256.update(data)  # read in 16MB chunks, not whole autoloader
	finally:
		f.close()
	return sha256.hexdigest()

# SHA-384
def sha384hash(filepath, blocksize=16 * 1024 * 1024):
	sha384 = hashlib.sha384()
	f = open(filepath, 'rb')
	try:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			sha384.update(data)  # read in 16MB chunks, not whole autoloader
	finally:
		f.close()
	return sha384.hexdigest()

# SHA-512
def sha512hash(filepath, blocksize=16 * 1024 * 1024):
	sha512 = hashlib.sha512()
	f = open(filepath, 'rb')
	try:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			sha512.update(data)  # read in 16MB chunks, not whole autoloader
	finally:
		f.close()
	return sha512.hexdigest()

# MD5
def md4hash(filepath, blocksize=16 * 1024 * 1024):
	md4 = hashlib.new('md4')
	f = open(filepath, 'rb')
	try:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			md4.update(data)  # read in 16MB chunks, not whole autoloader
	finally:
		f.close()
	return md4.hexdigest()


# MD5
def md5hash(filepath, blocksize=16 * 1024 * 1024):
	md5 = hashlib.md5()
	f = open(filepath, 'rb')
	try:
		while True:
			data = f.read(blocksize)
			if not data:
				break
			md5.update(data)  # read in 16MB chunks, not whole autoloader
	finally:
		f.close()
	return md5.hexdigest()

# Use choice of hash functions for all files in a directory
def verifier(workingdir, blocksize=16 * 1024 * 1024, crc32=False, adler32=False, sha1=True, sha224=False, sha256=False, sha384=False, sha512=False, md5=True, md4=False):
	target = open(os.path.join(workingdir, 'all.cksum'), 'w')
	hashoutput_crc32 = "CRC32\n"
	hashoutput_adler32 = "ADLER32\n"
	hashoutput_sha1 = "SHA1\n"
	hashoutput_sha224 = "SHA224\n"
	hashoutput_sha256 = "SHA256\n"
	hashoutput_sha384 = "SHA384\n"
	hashoutput_sha512 = "SHA512\n"
	hashoutput_md5 = "MD5\n"
	hashoutput_md4 = "MD4\n"
	for file in os.listdir(workingdir):
		if os.path.isdir(os.path.join(workingdir, file)):
			pass  # exclude folders
		elif file.endswith(".cksum"):
			pass  # exclude already generated files
		else:
			if adler32 == True:
				print("Adler32:", str(file))
				result_adler32 = adler32hash(os.path.join(workingdir, file), blocksize)
				hashoutput_adler32 += str(result_adler32.upper())
				hashoutput_adler32 += " "
				hashoutput_adler32 += str(file)
				hashoutput_adler32 += " \n"
			if crc32 == True:
				print("CRC32:", str(file))
				result_crc32 = crc32hash(os.path.join(workingdir, file), blocksize)
				hashoutput_crc32 += str(result_crc32.upper())
				hashoutput_crc32 += " "
				hashoutput_crc32 += str(file)
				hashoutput_crc32 += " \n"
			if md4 == True:
				print("MD4:", str(file))
				result_md4 = md4hash(os.path.join(workingdir, file), blocksize)
				hashoutput_md4 += str(result_md4.upper())
				hashoutput_md4 += " "
				hashoutput_md4 += str(file)
				hashoutput_md4 += " \n"
			if md5 == True:
				print("MD5:", str(file))
				result_md5 = md5hash(os.path.join(workingdir, file), blocksize)
				hashoutput_md5 += str(result_md5.upper())
				hashoutput_md5 += " "
				hashoutput_md5 += str(file)
				hashoutput_md5 += " \n"
			if sha1 == True:
				print("SHA1:", str(file))
				result_sha1 = sha1hash(os.path.join(workingdir, file), blocksize)
				hashoutput_sha1 += str(result_sha1.upper())
				hashoutput_sha1 += " "
				hashoutput_sha1 += str(file)
				hashoutput_sha1 += " \n"
			if sha224 == True:
				print("SHA224:", str(file))
				result_sha224 = sha224hash(os.path.join(workingdir, file), blocksize)
				hashoutput_sha224 += str(result_sha224.upper())
				hashoutput_sha224 += " "
				hashoutput_sha224 += str(file)
				hashoutput_sha224 += " \n"
			if sha256 == True:
				print("SHA256:", str(file))
				result_sha256 = sha256hash(os.path.join(workingdir, file), blocksize)
				hashoutput_sha256 += str(result_sha256.upper())
				hashoutput_sha256 += " "
				hashoutput_sha256 += str(file)
				hashoutput_sha256 += " \n"
			if sha384 == True:
				print("SHA384:", str(file))
				result_sha384 = sha384hash(os.path.join(workingdir, file), blocksize)
				hashoutput_sha384 += str(result_sha384.upper())
				hashoutput_sha384 += " "
				hashoutput_sha384 += str(file)
				hashoutput_sha384 += " \n"
			if sha512 == True:
				print("SHA512:", str(file))
				result_sha512 = sha512hash(os.path.join(workingdir, file), blocksize)
				hashoutput_sha512 += str(result_sha512.upper())
				hashoutput_sha512 += " "
				hashoutput_sha512 += str(file)
				hashoutput_sha512 += " \n"
			print("\n")
	if adler32 == True:
		target.write(hashoutput_adler32 + "\n")
	if crc32 == True:
		target.write(hashoutput_crc32 + "\n")
	if md4 == True:
		target.write(hashoutput_md4 + "\n")
	if md5 == True:
		target.write(hashoutput_md5 + "\n")
	if sha1 == True:
		target.write(hashoutput_sha1 + "\n")
	if sha224 == True:
		target.write(hashoutput_sha224 + "\n")
	if sha256 == True:
		target.write(hashoutput_sha256 + "\n")
	if sha384 == True:
		target.write(hashoutput_sha384 + "\n")
	if sha512 == True:
		target.write(hashoutput_sha512 + "\n")
	target.close()

import zlib
import hashlib
import os

#Hash/verification functions; perform operation on specific file
#CRC32
def crc32(filepath):
    buf = open(filepath, 'rb').read()
    buf = (zlib.crc32(buf) & 0xFFFFFFFF)
    return "%08X" % buf
#Adler32
def adler32(filepath):
    buf = open(filepath, 'rb').read()
    buf = (zlib.adler32(buf) & 0xFFFFFFFF)
    return "%08X" % buf

#SHA-1
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

#SHA-224
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

#SHA-256
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

#SHA-384
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

#SHA-512
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

#MD5
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

#Use choice of hash functions for all files in a directory
def verify(workingdir, blocksize=16*1024 *1024, crc32=False, adler32=False, sha1=True, sha224=False, sha256=False, sha384=False, sha512=False, md5=True):
        hashoutput_crc32 = "CRC32\n"
        hashoutput_adler32 = "Adler32\n"
        hashoutput_sha1 = "SHA1\n"
        hashoutput_sha224 = "SHA224\n"
        hashoutput_sha256 = "SHA256\n"
        hashoutput_sha384 = "SHA384\n"
        hashoutput_sha512 = "SHA512\n"
        hashoutput_md5 = "MD5\n"
        for file in os.listdir(workingdir):
            if os.path.isdir(os.path.join(workingdir, file)):
                pass  # exclude folders
            elif file.endswith(".cksum"):
                pass  # exclude already generated files
            else:
                if crc32==True:
                    result_crc32 = crc32(os.path.join(workingdir, file))
                    hashoutput_crc32 += str(result_crc32)
                    hashoutput_crc32 += " "
                    hashoutput_crc32 += str(file)
                    hashoutput_crc32 += " "
                    hashoutput_crc32 += str(file.size() + " bytes")
                    hashoutput_crc32 += " \n"
                if adler32==True:
                    result_adler32 = adler32(os.path.join(workingdir, file))
                    hashoutput_adler32 += str(result_adler32)
                    hashoutput_adler32 += " "
                    hashoutput_adler32 += str(file)
                    hashoutput_adler32 += " "
                    hashoutput_adler32 += str(file.size() + " bytes")
                    hashoutput_adler32 += " \n"
                if sha1==True:
                    result_sha1 = sha1hash(os.path.join(workingdir, file))
                    hashoutput_sha1 += str(result_sha1)
                    hashoutput_sha1 += " "
                    hashoutput_sha1 += str(file)
                    hashoutput_sha1 += " "
                    hashoutput_sha1 += str(file.size() + " bytes")
                    hashoutput_sha1 += " \n"
                if sha224==True:
                    result_sha224 = sha224hash(os.path.join(workingdir, file))
                    hashoutput_sha224 += str(result_sha224)
                    hashoutput_sha224 += " "
                    hashoutput_sha224 += str(file)
                    hashoutput_sha224 += " "
                    hashoutput_sha224 += str(file.size() + " bytes")
                    hashoutput_sha224 += " \n"
                if sha256==True:
                    result_sha256 = sha256hash(os.path.join(workingdir, file))
                    hashoutput_sha256 += str(result_sha256)
                    hashoutput_sha256 += " "
                    hashoutput_sha256 += str(file)
                    hashoutput_sha256 += " "
                    hashoutput_sha256 += str(file.size() + " bytes")
                    hashoutput_sha256 += " \n"
                if sha384==True:
                    result_sha384 = sha384hash(os.path.join(workingdir, file))
                    hashoutput_sha384 += str(result_sha384)
                    hashoutput_sha384 += " "
                    hashoutput_sha384 += str(file)
                    hashoutput_sha384 += " "
                    hashoutput_sha384 += str(file.size() + " bytes")
                    hashoutput_sha384 += " \n"
                if sha512==True:
                    result_sha512 = sha512hash(os.path.join(workingdir, file))
                    hashoutput_sha512 += str(result_sha512)
                    hashoutput_sha512 += " "
                    hashoutput_sha512 += str(file)
                    hashoutput_sha512 += " "
                    hashoutput_sha512 += str(file.size() + " bytes")
                    hashoutput_sha512 += " \n"
                if md5==True:
                    result_md5 = md5hash(os.path.join(workingdir, file))
                    hashoutput_md5 += str(result_md5)
                    hashoutput_md5 += " "
                    hashoutput_md5 += str(file)
                    hashoutput_md5 += " "
                    hashoutput_md5 += str(file.size() + " bytes")
                    hashoutput_md5 += " \n"
        target = open(os.path.join(workingdir, 'all.cksum'), 'w')
        if crc32==True:
            target.write(hashoutput_crc32)
        if adler32==True:
            target.write(hashoutput_adler32)
        if sha1==True:
            target.write(hashoutput_sha1)
        if sha224==True:
            target.write(hashoutput_sha224)
        if sha256==True:
            target.write(hashoutput_sha256)
        if sha384==True:
            target.write(hashoutput_sha384)
        if sha512==True:
            target.write(hashoutput_sha512)
        if md5==True:
            target.write(hashoutput_md5)
        target.close()
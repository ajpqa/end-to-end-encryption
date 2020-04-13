#https://mkyong.com/python/python-how-to-list-all-files-in-a-directory/
#https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files
#https://stackoverflow.com/questions/1035340/reading-binary-file-and-looping-over-each-byte

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import shutil
import time

class KMS:
    master_key = ""
    dek_db = {}
    kek_db = {}

path = '.'
path_secure = './secure/'
path_unsecure = './unsecure/'

chunk_size = 256

#Clean folders
shutil.rmtree(path_secure,ignore_errors=True)
shutil.rmtree(path_unsecure,ignore_errors=True)
os.mkdir(path_secure)
os.mkdir(path_unsecure)


def listFiles():
  #List files in folder
  files = []
  # r=root, d=directories, f = files
  for r, d, f in os.walk(path):
      for file in f:
          if '.txt' in file:
              files.append(os.path.join(r, file))

  for f in files:
      print(f)

def encrypt(file_to_encrypt):
    #get key
    key = b'01234567890123456789012345678901'
    
    #generate random 96 bit IV
    #iv = os.urandom(12)
    iv = bytes("012345678901", "utf-8")

    #construct AES_GCM cipher with given key and the random IV
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()

    #get associated data
    stats = os.stat(file_to_encrypt)
    #aad = ""
    print(stats)
    #for stat in stats:
    #    print(stat)
    #    aad += str(stat) 
    #    print(str(aad))

    aad = str(stats.st_size)

    #authenticate associated data
    encryptor.authenticate_additional_data(aad.encode())

    #PUT: Encrypt a file into secure folder
    #file_to_put="ejemplo.txt"
    with open(file_to_encrypt, "rb") as source, open(path_secure+file_to_encrypt, "wb+") as sink:
        byte = source.read(chunk_size)
        while byte:
            sink.write(encryptor.update(byte))
            # Do stuff with byte
            byte = source.read(chunk_size)
	
        source.close()
        sink.close()
    encryptor.finalize()

    return encryptor.tag

def decrypt(file_to_decrypt, tag):
    #Use a static Master Key to protect all files. 
    iv = bytes("012345678901",'utf-8')
    key = bytes("01234567890123456789012345678901",'utf-8')

    #get associated data
    stats = os.stat(path_secure + file_to_decrypt)
    #aad = ""
    #for stat in stats:
    #    aad += str(stat)
    #print(str(aad))
    aad = str(stats.st_size)

    #construct AES_GCM cipher with given key and the generated iv
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

    #authenticate associated data
    decryptor.authenticate_additional_data(aad.encode())

    #GET: Encrypt a file into secure folder 
    with open(path_secure+file_to_decrypt, "rb") as source, open(path_unsecure+file_to_decrypt, "wb+") as sink:
        byte = source.read(chunk_size)
        while byte:
            sink.write(decryptor.update(byte))
            # Do stuff with byte.
            byte = source.read(chunk_size)
        sink.write(decryptor.finalize())
        source.close()
        sink.close()

listFiles()
print("put")
tag = encrypt("ejemplo.txt")
listFiles()
print("get")
decrypt("ejemplo.txt", tag)
listFiles()

#https://mkyong.com/python/python-how-to-list-all-files-in-a-directory/
#https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files
#https://stackoverflow.com/questions/1035340/reading-binary-file-and-looping-over-each-byte

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os
import shutil

path = '.'
path_secure = './secure/'
path_unsecure = './unsecure/'

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

def putEncryptedFile():

  chunk_size = 256

  #Use a static Master Key to protect all files. 
  nonce = bytes("0123456789012345",'utf-8')
  key = bytes("01234567890123456789012345678901",'utf-8')

  #Ferment doesn't implemt the update pattern, so I am using a stream cipher instead.
  algorithm = algorithms.ChaCha20(key, nonce)
  cipher = Cipher(algorithm, mode=None, backend=default_backend())
  encryptor = cipher.encryptor()

  #PUT: Encrypt a file into secure folder 
  file_to_put="ejemplo.txt"
  with open(file_to_put, "rb") as source, open(path_secure+file_to_put, "wb+") as sink:
      byte = source.read(chunk_size)
      while byte:
          sink.write(encryptor.update(byte))
          # Do stuff with byte.
          byte = source.read(chunk_size)
      source.close()
      sink.close()

def getEncryptedFile():

  chunk_size = 256

  #Use a static Master Key to protect all files. 
  nonce = bytes("0123456789012345",'utf-8')
  key = bytes("01234567890123456789012345678901",'utf-8')

  #Ferment doesn't implemt the update pattern, so I am using a stream cipher instead.
  algorithm = algorithms.ChaCha20(key, nonce)
  cipher = Cipher(algorithm, mode=None, backend=default_backend())

  decryptor = cipher.decryptor()

  #GET: Encrypt a file into secure folder 
  file_to_get="ejemplo.txt"
  with open(path_secure+file_to_get, "rb") as source, open(path_unsecure+file_to_get, "wb+") as sink:
      byte = source.read(chunk_size)
      while byte:
          sink.write(decryptor.update(byte))
          # Do stuff with byte.
          byte = source.read(chunk_size)
      source.close()
      sink.close()

listFiles()
print("put")
putEncryptedFile()
listFiles()
print("get")
getEncryptedFile()
listFiles()

#https://mkyong.com/python/python-how-to-list-all-files-in-a-directory/
#https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files
#https://stackoverflow.com/questions/1035340/reading-binary-file-and-looping-over-each-byte

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import shutil
import time

class KMS:
    def __init__(self):
        self.kek = Fernet.generate_key()
        self.dek_db = {}
        self.users = {}
        self.currentUser = ""

    def existUsers(self):
        if self.users:
            return True
        return False

    def existUser(self, username):
        if username in self.users:
            return True
        return False

    def addUser(self, username):
        self.users.update({username: [username]})

    def getUsers(self):
        return [name for name in self.users]

    def setCurrentUser(self, username):
        self.currentUser = username

    def addFolderAccess(self, folder_path, usernames):
        for name in usernames:
            self.users[name].append(folder_path)

    def userHasAccess(self, username, folder_path):
        folder_path = folder_path.replace("./secure/", "").replace("./unsecure/", "")
        if folder_path in self.users[username]:
            return True
        return False

    def addFilename(self, file_name):
        self.dek_db.update({file_name: {}})

    def addAlgoName(self, file_name, algo_name):
        self.dek_db[file_name].update({'algo_name': algo_name})

    def addDek(self, file_name, dek, tag, iv):
        f = Fernet(self.kek)
        dek = f.encrypt(dek)
        self.dek_db[file_name].update({'dek': dek, 'tag': tag, 'iv': iv})

    def getDek(self, file_name):
        f = Fernet(self.kek)
        db = self.dek_db[file_name]
        dek = f.decrypt(db['dek'])
        return dek
    
    def getAlgoName(self, file_name):
        return self.dek_db[file_name]['algo_name']

    def getTag(self, file_name):
        return self.dek_db[file_name]['tag']

    def getIv(self, file_name):
        return self.dek_db[file_name]['iv']

    def encrypt(self, file_name):
        tag = None
        
        #generate random 256 bit data encryption key
        dek = os.urandom(32)
        
        #generate random 128 bit IV
        iv = os.urandom(16)

        algorithm = algorithms.AES(dek)

        algo_name = self.getAlgoName(file_name)
        
        if algo_name == "aes":
            mode = modes.GCM(iv)
        else:
            mode = modes.OFB(iv)
            algorithm = algorithms.Camellia(dek)

        #construct AES_GCM cipher with given dek and the random IV
        encryptor = Cipher(algorithm, mode, backend=default_backend()).encryptor()
        
        if algo_name == "aes":
            #get associated data
            stats = os.stat(file_name)
            aad = str(stats.st_size)

            #authenticate associated data
            encryptor.authenticate_additional_data(aad.encode())

        #PUT: Encrypt a file into secure folder
        with open(file_name, "rb") as source, open(path_secure + self.currentUser + '/' + file_name, "wb+") as sink:
            byte = source.read(chunk_size)
            while byte:
                sink.write(encryptor.update(byte))
                # Do stuff with byte
                byte = source.read(chunk_size)
            source.close()
            sink.close()
        encryptor.finalize()
        
        if algo_name == "aes":
            tag = encryptor.tag

        self.addDek(file_name, dek, tag, iv)

    def decrypt(self, file_name):
        #get iv and dek
        iv = self.getIv(file_name)
        dek = self.getDek(file_name)
        algo_name = self.getAlgoName(file_name)
        tag = self.getTag(file_name)

        algorithm = algorithms.Camellia(dek)
        mode = modes.OFB(iv)

        if algo_name == "aes":
            #get associated data
            stats = os.stat(path_secure + self.currentUser + '/' + file_name)
            aad = str(stats.st_size)
            algorithm = algorithms.AES(dek)
            mode = modes.GCM(iv, tag)

        #construct AES_GCM cipher with given dek and the generated iv
        decryptor = Cipher(algorithm, mode, backend=default_backend()).decryptor()
        
        if algo_name == "aes":
            #authenticate associated data
            decryptor.authenticate_additional_data(aad.encode())

        #GET: Encrypt a file into secure folder 
        with open(path_secure + self.currentUser + '/' + file_name, "rb") as source, open(path_unsecure + self.currentUser + '/' + file_name, "wb+") as sink:
            byte = source.read(chunk_size)
            while byte:
                sink.write(decryptor.update(byte))
                # Do stuff with byte.
                byte = source.read(chunk_size)
            source.close()
            sink.close()
        decryptor.finalize()

kms = KMS()

path = '.'
path_secure = './secure/'
path_unsecure = './unsecure/'

chunk_size = 256

algo_names = ['aes', 'camellia']

def listFiles(username):
  #list all files in current directory outside of cloud storage
  files = [f for f in os.listdir('.') if os.path.isfile(f) and '.txt' in f]
  #list all files in folders of current user
  # r=root, d=directories, f = files
  for r, d, f in os.walk(path):
      if kms.userHasAccess(username, r):
        for file in f:
            if '.txt' in file:
                files.append(os.path.join(r, file))

  for f in files:
      print(f)

def createFolder(folder_path, usernames):
    os.mkdir(path_secure + folder_path)
    os.mkdir(path_unsecure + folder_path)
    kms.addFolderAccess(folder_path, usernames)

def deleteFile(username, file_path):
    if kms.userHasAccess(username, "/".join(file_path.plit("/")[:-1])):
        os.remove(file_path)

def clearUnsecureFolder(username):
    os.removedirs(path_unsecure + username)
    os.mkdir(path_unsecure + username)

#Clean folders
shutil.rmtree(path_secure,ignore_errors=True)
shutil.rmtree(path_unsecure,ignore_errors=True)
os.mkdir(path_secure)
os.mkdir(path_unsecure)


choice = '1'
username = ""
while True:
    if kms.existUsers():
        while True:
            print("1 Login\n2 Create a new User")
            choice = input()
            if choice in ['1', '2']:
                break
        if choice == '1':
            while True:
                username = input("Username: ")
                if kms.existUser(username):
                    break
                else:
                    print("User doesn't exist.")
        else:
            while True:
                username = input("Username: ")
                if kms.existUser(username):
                    print("User already exists.\n")
                else:
                    kms.addUser(username)
                    createFolder(username, [username])
                    break
    else:
        print("Create a new user.")
        username = input("Username: ")
        kms.addUser(username)
        createFolder(username, [username])

    kms.setCurrentUser(username)
            
    while True:
        while True:
            print("Logged in as user: " + username)
            print("What do you want to do?\n 1 Put a file in secure storage\n 2 Get a file from secure storage\n 3 List my files\n 4 Create a new folder\n 5 Logout\n")
            choice = input()
            if choice in ['1', '2', '3', '4', '5']:
                break

        if choice == '1':
            print("Which file do you want to put in the secure storage?\n")
            file_name = input()
            if os.path.isfile(file_name):
                while True:
                    print("Which type of encryption do you want to use?\n 1 AES with GCM (aead)\n 2 Camellia with OFB (no aead)\n")
                    algorithm = input()
                    if algorithm in ['1', '2']:
                        break
                kms.addFilename(file_name)
                algo_name = algo_names[int(algorithm)-1]
                kms.addAlgoName(file_name, algo_name)
                kms.encrypt(file_name)
            else:
                print("File doesn't exist.\n")
        elif choice == '2':
            print("Which file do you want to get from the secure storage?\n")
            file_name = input()
            if os.path.isfile(file_name):
                kms.decrypt(file_name)
            else:
                print("File doesn't exist.\n")
        elif choice == '3':
            listFiles(username)
        elif choice == '4':
            usernames = [username]
            folder_path = input("Path of the folder: ")
            while True:
                other_users  = [user for user in kms.getUsers() if user not in usernames]
                if not other_users:
                    break
                print("Do you want to add more users?")
                x = 1
                print(" " + str(x) + " Add no more users.")
                for user in other_users:
                    x += 1
                    print(" " + str(x) + " " + user)
                user_choice = input()
                if int(user_choice) in range(1, x+1, 1):
                    if user_choice == '1':
                        break
                    else:
                        usernames.append(other_users[int(user_choice) - 2]) 
            createFolder(folder_path, usernames)
        else:
            break




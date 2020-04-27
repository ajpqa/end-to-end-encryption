#https://mkyong.com/python/python-how-to-list-all-files-in-a-directory/
#https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files
#https://stackoverflow.com/questions/1035340/reading-binary-file-and-looping-over-each-byte

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import shutil
import time
import os


class KMS:
    def __init__(self):
        self.kek_db = {} #{folder: {decryption_kek: <kek used to encrypt deks of that folder the last time they were accessed>, encryption_kek: <kek that will be used to re-encrypt the deks the next time they are accessed>}}
        self.pwd_db = {} #{folder: <folder password hash to verify entered password is correct>}
        self.dek_db = {} #{file_name: {algo_name: <name of algorithm used to encrypt the file>, dek: <encrypted data encryption key>, tag: <tag used to authenticate the data>, iv: <initialization vector>}}
        self.users = {} #{username: {pwd: <user password hash>, folders: {folder: <folder password encrypted with user password>}}}
        self.currentUser = ""

    def addFolderKek(self, folder_path):
        #set folder password which allows user to gain access to shared_folder
        folder_pwd = input("Set folder password used for first access: ")

        #store hash of folder password to verify that entered password is the correct one later
        kdf = Scrypt(salt=self.users[self.currentUser]["salt"], length=32, n=2**4, r=8, p=1, backend=default_backend())
        key = kdf.derive(folder_pwd.encode()) 
        self.pwd_db.update({folder_path: key})

        #generate kek of folder
        generated_kek = Fernet.generate_key()

        #encrypt the kek using the folder password and store the encrypted kek
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        folder_key = kdf.derive(folder_pwd.encode())
        f = Fernet(urlsafe_b64encode(folder_key))
        folder_kek = f.encrypt(generated_kek)
        self.kek_db.update({folder_path: {"decryption_kek": folder_kek, "encryption_kek": folder_kek, "salt": salt}})

        #store folder password encrypted with user password
        while True:
            user_pwd = input("Enter your user password: ")
            kdf = Scrypt(salt=self.users[self.currentUser]["salt"], length=32, n=2**4, r=8, p=1, backend=default_backend())
            try:
                kdf.verify(user_pwd.encode(), self.users[self.currentUser]["pwd"])
            except InvalidKey:
                print("The password is wrong.")
                continue
            else:
                break
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.users[self.currentUser]["salt"], iterations=100000, backend=default_backend())
        user_key = kdf.derive(user_pwd.encode())
        f = Fernet(urlsafe_b64encode(user_key))
        encrypted_folder_pwd = f.encrypt(folder_pwd.encode())
        print("\n encrypted folder pw: " + encrypted_folder_pwd.decode() + "\nfolder path: " + folder_path + "\n")
        print("CODE: " + urlsafe_b64encode(user_key).decode())
        self.users[self.currentUser]["folders"].update({folder_path: encrypted_folder_pwd})

    def getEncryptionFolderKek(self, folder_path):
        encryption_kek = self.kek_db[folder_path]["encryption_kek"]
        #dek will be encrypted with encryption kek which could be a new one after rotation -> decryption kek will be set to encryption kek
        self.kek_db[folder_path].update({"decryption_kek": encryption_kek})
        return  encryption_kek

    def getDecryptionFolderKek(self, folder_path):
        return self.kek_db[folder_path]["decryption_kek"]

    def existUsers(self):
        if self.users:
            return True
        return False

    def existUser(self, username):
        if username in self.users:
            return True
        return False

    def addUser(self, username):
        pwd = input("Set your password: ")
        salt = os.urandom(16)
        #derive
        kdf = Scrypt(salt=salt, length=32, n=2**4, r=8, p=1, backend=default_backend())
        key = kdf.derive(pwd.encode())
        self.users.update({username: {"pwd": key, "salt": salt, "folders": {}}})

    def getUsers(self):
        return [name for name in self.users]

    def setCurrentUser(self, username):
        self.currentUser = username

    def addFolderAccess(self, folder_path, usernames):
        for username in usernames:
            self.users[username]["folders"].update({folder_path: None})
    
    def getAllAccessableFolders(self, username):
        return list(self.users[username]["folders"].keys())

    def userHasAccess(self, username, folder_path):
        folder_path = folder_path.replace("./secure/", "").replace("./unsecure/", "")
        if folder_path in self.users[username]["folders"]:
            return True
        return False

    def addFilename(self, file_name):
        self.dek_db.update({file_name: {}})

    def addAlgoName(self, file_name, algo_name):
        self.dek_db[file_name].update({'algo_name': algo_name})

    def addDek(self, file_name, dek, tag, iv):
        folder_path = "/".join(file_name.split("/")[0:-1])
        while True:
            pwd = input("user  password: ")
            kdf = Scrypt(salt=self.users[self.currentUser]["salt"], length=32, n=2**4, r=8, p=1, backend=default_backend())
            try:
                kdf.verify(pwd.encode(), self.users[self.currentUser]["pwd"])
            except InvalidKey:
                print("The password is wrong.")
                continue
            else:
                break

        #get encrypted folder password and encrypted kek
        encrypted_folder_pwd = self.users[self.currentUser]["folders"][folder_path]
        stored_kek = self.getEncryptionFolderKek(folder_path)

        print("\n encrypted folder pwd 2: " + encrypted_folder_pwd.decode() + "\n folder path: " + folder_path + "\n")

        #decrypt folder password using the user password
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.users[self.currentUser]["salt"], iterations=100000, backend=default_backend())
        pwd_key = kdf.derive(pwd.encode())

        print("CODE: " + urlsafe_b64encode(pwd_key).decode())
        f = Fernet(urlsafe_b64encode(pwd_key))
        folder_pwd = f.decrypt(encrypted_folder_pwd)

        #decrypt the kek using the decrypted folder password
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.kek_db[folder_path]["salt"], iterations=100000, backend=default_backend())
        folder_key = kdf.derive(folder_pwd)
        f = Fernet(urlsafe_b64encode(folder_key))
        folder_kek = f.decrypt(stored_kek)

        #encrypt dek using the decrypted folder kek
        f = Fernet(folder_kek)
        dek = f.encrypt(dek)
        self.dek_db[file_name].update({'dek': dek, 'tag': tag, 'iv': iv})

    def getDek(self, file_name):
        folder_path = "/".join(file_name.split("/")[0:-1])
        while True:
            pwd = input("Enter your user password")
            kdf = Scrypt(salt=self.users[self.currentUser]["salt"], length=32, n=2**4, r=8, p=1, backend=default_backend())
            try:
                kdf.verify(pwd.encode(), self.users[self.currentUser]["pwd"])
            except InvalidKey:
                print("The password is wrong.")
                continue
            else:
                break
        
        #get encrypted folder password and folder kek
        encrypted_folder_pwd = self.users[self.currentUser]["folders"][folder_path]
        encrypted_kek = self.getDecryptionFolderKek(folder_path)

        #decrypt folder password
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.users[self.currentUser]["salt"], iterations=100000, backend=default_backend())
        pwd_key = kdf.derive(pwd.encode())
        f = Fernet(urlsafe_b64encode(pwd_key))
        folder_pwd = f.decrypt(encrypted_folder_pwd)

        #decrypt kek
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.kek_db[folder_path]["salt"], iterations=100000, backend=default_backend())
        folder_key = kdf.derive(folder_pwd)
        f = Fernet(urlsafe_b64encode(folder_key))
        kek = f.decrypt(encrypted_kek)

        #decrypt dek
        f = Fernet(kek)
        dek = f.decrypt(self.dek_db[file_name]['dek'])
        return dek
    
    def getAlgoName(self, file_name):
        return self.dek_db[file_name]['algo_name']

    def getTag(self, file_name):
        return self.dek_db[file_name]['tag']

    def getIv(self, file_name):
        return self.dek_db[file_name]['iv']

    def firstAccessToFolder(self, folder_path):
        if self.users[self.currentUser]["folders"][folder_path]:
            return False
        return True

    def enterFolderPwd(self, folder_path):
        while True:
            folder_pwd = input("This is your first access to this folder. Please enter the folder password: ")
            kdf = Scrypt(salt=self.users[self.currentUser]["salt"], length=32, n=2**4, r=8, p=1, backend=default_backend())
            try:
                kdf.verify(folder_pwd.encode(), self.pwd_db[folder_path])
            except InvalidKey:
                print("The password is wrong.")
                continue
            else:
                break

        print("Folder password will be stored for access in the future.")

        while True:
            pwd = input("Please enter the user password: ")
            kdf = Scrypt(salt=self.users[self.currentUser]["salt"], length=32, n=2**4, r=8, p=1, backend=default_backend())
            try:
                kdf.verify(pwd.encode(), self.users[self.currentUser]["pwd"])
            except InvalidKey:
                print("The password is wrong.")
                continue
            else:
                break
        
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.users[self.currentUser]["salt"], iterations=100000, backend=default_backend())
        pwd_key = kdf.derive(pwd.encode())
        f = Fernet(urlsafe_b64encode(pwd_key))
        encrypted_folder_pwd = f.eccrypt(folder_pwd)
        self.users[self.currentUser]["folders"].update({folder_path: encrypted_folder_pwd})

    def encrypt(self, folder_path, file_name):
        #if first access to shared folder then the user needs to enter the folder password
        if self.firstAccessToFolder(folder_path):
            self.enterFolderPwd(folder_path)
        
        tag = None
        
        #generate random 256 bit data encryption key
        dek = os.urandom(32)
        
        #generate random 128 bit IV
        iv = os.urandom(16)

        algorithm = algorithms.AES(dek)

        algo_name = self.getAlgoName(folder_path + "/" + file_name)
        
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
        with open(file_name, "rb") as source, open(path_secure + folder_path + "/" + file_name, "wb+") as sink:
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

        self.addDek(folder_path + "/" + file_name, dek, tag, iv)

    def decrypt(self, file_name):
        folder_path = "/".join(file_name.split("/")[0:-1])

        #if first access to folder then the user has to enter folder password
        if self.firstAccessToFolder(folder_path):
            self.enterFolderPwd(folder_path)
            
        #get iv, dek, algo_name and authentication tag
        iv = self.getIv(file_name)
        dek = self.getDek(file_name)
        algo_name = self.getAlgoName(file_name)
        tag = self.getTag(file_name)

        algorithm = algorithms.Camellia(dek)
        mode = modes.OFB(iv)

        if algo_name == "aes":
            #get associated data
            stats = os.stat(path_secure + file_name)
            aad = str(stats.st_size)
            algorithm = algorithms.AES(dek)
            mode = modes.GCM(iv, tag)

        #construct AES_GCM cipher with given dek and the generated iv
        decryptor = Cipher(algorithm, mode, backend=default_backend()).decryptor()
        
        if algo_name == "aes":
            #authenticate associated data
            decryptor.authenticate_additional_data(aad.encode())

        #GET: Encrypt a file into secure folder 
        with open(path_secure + file_name, "rb") as source, open(path_unsecure + file_name, "wb+") as sink:
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
    kms.addFolderKek(folder_path)

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

file = open("ejemplo.txt", "wb+")
file.write(b"This is an example.")
file.close()

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
                    kms.setCurrentUser(username)
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
                    kms.setCurrentUser(username)
                    createFolder(username, [username])
                    break
    else:
        print("Create a new user.")
        username = input("Username: ")
        kms.addUser(username)
        kms.setCurrentUser(username)
        createFolder(username, [username])

            
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
                
                while True:
                    print("In which directory do you want to put the file?")
                    i = 1
                    for d in kms.getAllAccessableFolders(username):
                        print(" " + str(i) + " /" + d + "/")
                        i += 1
                    dir_choice = input()
                    if int(dir_choice) in range(1, len(kms.getAllAccessableFolders(username))+1, 1):
                        break
                folder_path = kms.getAllAccessableFolders(username)[int(dir_choice)-1]
                kms.addFilename(folder_path + "/" + file_name)
                algo_name = algo_names[int(algorithm)-1]
                kms.addAlgoName(folder_path + "/" + file_name, algo_name)
                kms.encrypt(folder_path, file_name)
                #os.remove(file_name)
            else:
                print("File doesn't exist.\n")
        elif choice == '2':
            print("Which file do you want to get from the secure storage?\n")
            file_name = input()
            if '/' in file_name and os.path.isfile(path_secure + file_name) or os.path.isfile(path_secure + username + '/' + file_name):
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




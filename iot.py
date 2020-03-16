#import paho-mqtt # https://python.org/pypi/paho-mqtt
import paho.mqtt.client as mqtt

# 1. Iot -> S : publish "register" Pu_IoT_DH
# 2. S -> FF :  publish "pu_S" Pu_S_DH 
# 3. S, IoT : Generate K_s
# 4. IoT: Generate Code = Random (6 digitos)
# 5. IoT: Show Code
# 6. IoT - S : publish "auth" E_K_S(Code)
# 7. S : Verify Code received = Code shown

import secrets
import base64
import random
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.serialization import ParameterFormat, PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import time

import json

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
  print("Connected with result code "+str(rc))

  # Subscribing in on_connect() means that if we lose the connection and
  # reconnect then subscriptions will be renewed.
  client.subscribe("newDeviceResponse")
  client.subscribe("authenticateResonse")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):

  if msg.topic == "newDeviceResponse":
    payload = json.loads(msg.payload)
    #only react to messages adressed to this device
    if payload['id'] == device_id:
      getSharedKey(payload)
  
  #would be used to select topics
  elif msg.topic == "authenticateResponse":
    payload = json.loads(msg.payload)
    authenticatePlatformAndGetTopic(payload)

def authenticatePlatformAndGetTopic(payload):
  h = hmac.HMAC(bytes.fromhex(master_key), hashes.SHA256(), backend=default_backend())
  h.update(payload['channel'].decode())

  h.verify(bytes.fromhex(payload['hmac']))

  keys.update({'topic': payload['channel']})

#function does first half of key exchange
#standard Diffie-Hellman and elliptic curve Diffie-Hellman are supported
def establishConnection(client, device_id):
  global keys

  choice = 1

  print("Exchange new key with platform.")

  if keys['type'] == '':
    while True:
      try:
        print("How do you want to exchange the key?\n 1 Diffie Hellman with HMAC\n 2 Elliptic curve exchange with HMAC")
        choice=int(input())
        if choice not in [1,2]:
          print("That's not a valid choice.\n")
          continue
      except ValueError:
        print("This is not a whole number.")
        continue
      break
  data = {}   
  
  if choice == 2:
    #generate public and private key
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    #public data to be shared with platform
    data = {'id': device_id, 'type': 'ecdhe', 'x': public_key.public_numbers().x, 'y': public_key.public_numbers().y}

    #store private key
    keys.update({'private_key': private_key})

    #store chosen type of key exchange algorithm for later exchanges during key rotation
    keys.update({'type':'ecdhe'})

  elif choice == 1:
    backend = default_backend()
    parameters = dh.generate_parameters(generator=2, key_size=512,backend=default_backend())
    params_pem = parameters.parameter_bytes(Encoding.PEM,ParameterFormat.PKCS3) 

    #Generate private key and public key
    private_key = parameters.generate_private_key()
    a_public_key = private_key.public_key()

    #public data to be shared with platform
    data = {'g': parameters.parameter_numbers().g, 'p': parameters.parameter_numbers().p, 'public_key': a_public_key.public_numbers().y, 'id': device_id, 'type': 'dh'}

    #store type of exchange and private key
    keys.update({'private_key': private_key})
    keys.update({'type':'dh'})

  else:
    print("Something went wrong...")

  #send data as JSON to platform
  payload = json.dumps(data)
  client.publish("newDevice", payload, 1)

#function generates key for encryption using HMAC after the response of the platform
def getSharedKey(payload):
  global keys

  #standard diffie hellman
  if payload['type'] == 'dh':

    g = int(payload["g"])
    p = int(payload["p"])
    y = int(payload["public_key"])

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())

    #do key exchange
    shared_key = keys['private_key'].exchange(peer_public_key)
  
  #elliptic diffie hellman
  elif payload['type'] == 'ecdhe':
    peer_public_key = ec.EllipticCurvePublicNumbers(int(payload['x']), int(payload['y']), ec.SECP384R1()).public_key(default_backend())

    #do key exchange
    shared_key = keys['private_key'].exchange(ec.ECDH(), peer_public_key)

  #derive key of shared key
  derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)

  #get final key using HMAC and master key
  h = hmac.HMAC(bytes.fromhex(master_key), hashes.SHA256(), backend=default_backend())
  h.update(derived_key)
  derived_key = h.finalize()

  #store key that is used for encryption
  keys.update({'derived_key': derived_key})

#function that emulates the IoT device
def runDevice(device_id, client):  
  print('My device id is : ' + str(device_id) + "\n")

  encryptions = ["fernet", "aead"]
  choice = 0

  #let user choose encryption type
  #standard fernet or authenticated encryption with associated data are supported
  while True:
    print("Choose the type of encryption for this device.\n 1 fernet\n 2 aead")
    choice = input()
    if choice in ['1', '2']:
      break

  encryption = encryptions[int(choice) - 1]

  # Inicia una nueva hebra
  client.loop_start()

  #start key exchange
  establishConnection(client, device_id)

  #wait for answer of platform to end key exchange before sending messages
  while 'derived_key' not in keys:
    print("waiting for derived key")
    time.sleep(1)

  num_messages = 0

  #time stamps needed for key rotation after certain time
  start_time = datetime.now()
  current_time = datetime.now()
  while True:
    time_difference = current_time - start_time
    #generate a new key if enough time has passed
    if time_difference.seconds > 30:
      print("Generate new key.")
      establishConnection(client, device_id)

    #user chooses number of messages that should be sent to platform
    while True:
      try:
        num_messages=int(input("Number of messages to be sent:"))
      except ValueError:
        print("This is not a whole number.")
        continue
      break

    while num_messages > 0:
      #encrypt data with chosen encryption type
      if encryption == "fernet":
        key = base64.urlsafe_b64encode(keys['derived_key'])
        cipher = Fernet(key)
        data = os.urandom(10)
        print("The message is: " + str(data.hex()))
        encrypted_data = cipher.encrypt(data)
        dic = {'id': device_id, 'encryption': encryption, 'encrypted_data': encrypted_data.decode()}
      else:
        key = keys['derived_key']
        cipher = ChaCha20Poly1305(key)
        data = os.urandom(10)
        print("The message is: " + str(data.hex()))
        now = datetime.now()
        string_now = now.strftime("%m/%d/%Y, %H:%M:%S")
        aad = string_now.encode() #additiional data is time stamp
        nonce = os.urandom(12) #new nonce for every message
        encrypted_data = cipher.encrypt(nonce, data, aad)

        dic = {'id': device_id, 'encryption': encryption, 'encrypted_data': str(encrypted_data.hex()), 'nonce': str(nonce.hex()), 'aad': str(aad.hex())}

      #send JSON to platform
      message = json.dumps(dic)
      client.publish("messages", message, 1)
      num_messages -= 1
      
      #send one message every 5 seconds
      time.sleep(5)
      current_time = datetime.now()

#send authenticated device id to platform
def authenticate(master_key, device_id, client):
  #get hash
  h = hmac.HMAC(bytes.fromhex(master_key), hashes.SHA256(), backend=default_backend())
  h.update(bytes.fromhex(device_id))
  code = h.finalize()

  dic = {'id': device_id, 'hmac': str(code.hex())}

  #send JSON
  message = json.dumps(dic)
  client.publish('authentication', message, 1)

  print("Sent authentication message.")

#connect to MQTT broker and return client object
def startMqtt():
  client = mqtt.Client()
  client.on_connect = on_connect
  client.on_message = on_message

  client.username_pw_set("try","try")

  client.connect("broker.shiftr.io", 1883, 60)
  return client


#standard master key if no input or ouptut available at IoT device
master_key = '03574e16832140423cc63f5ba02cd2063d3c28e41a497aa471e75fb640ca3e1c'

#generate random device id
device_id = str(os.urandom(16).hex())

#global dict to store important values for device
keys = dict({'type':''})

#standard choice for device type
choice = '1'

#choose device type for authentication and exchanging device id
while True:
  print("Set up platform first then choose a device type.\n 1 IoT device has neither input nor output (static master key)\n 2 IoT device has Input device\n 3 IoT device has output device\n")
  choice = input()
  if choice in ['1','2','3']:
    break

if choice == '2':
  print("Enter the master key (as a hex number).")
  master_key = input()
elif choice == '3':
  master_key = str(os.urandom(16).hex())
  print("Master key : " + master_key)
  print("Enter this master key at the platform to enable authentication at the beginning of the connection.")
  print("Press Enter when you're done.")
  input()
  
#connect to broker
client = startMqtt()

#send device id in authenticated message
authenticate(master_key, device_id, client)

#start device simulation
runDevice(device_id, client)



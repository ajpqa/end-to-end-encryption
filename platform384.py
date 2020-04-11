#import paho-mqtt # https://python.org/pypi/paho-mqtt
import paho.mqtt.client as mqtt
import json

# 1. Iot -> S : publish "register" Pu_IoT_DH
# 2. S -> FF :  publish "pu_S" Pu_S_DH 
# 3. S, IoT : Generate K_s
# 4. IoT: Generate Code = Random (6 digitos)4
# 6. IoT - S : publish "auth" E_K_S(Code)
# 7. S : Verify Code received = Code shown

import secrets
import base64
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.serialization import ParameterFormat, PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.serialization import load_pem_parameters, load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import time

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
  print("Connected with result code "+str(rc))

  # Subscribing in on_connect() means that if we lose the connection and
  # reconnect then subscriptions will be renewed.
  client.subscribe("newDevice")
  client.subscribe("messages")
  client.subscribe("authentication")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
  if msg.topic == 'newDevice': #key exchange
    payload = json.loads(msg.payload)
    newDevice(client, payload)
  elif msg.topic == 'authentication': #register new device
    payload = json.loads(msg.payload)
    authenticate(payload, client)
  else:
    payload = json.loads(msg.payload) #encrypted message
    decrypt(client, payload, msg.topic)

#function to exchnage key with IoT device
#id of IoT device needs to be stored before key exchange (through function authneticate(payload, client))
def newDevice(client, payload):
  device_id = payload["id"]

  #device id needs to be stored before key exchange
  if device_id not in devices.keys():
    print("Device needs to authenticate")
    return 1

  #initialize shared key
  shared_key = os.urandom(32)
   
  if payload['type'] == 'dh':
    #generate peer public key from sent parameters
    g = int(payload["g"])
    p = int(payload["p"])
    y = int(payload["public_key"])
    
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())

    #generate own keys using the sent parameters
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    #send the public data back to the IoT device
    data = {'g': parameters.parameter_numbers().g, 'p': parameters.parameter_numbers().p, 'public_key': public_key.public_numbers().y, 'id': device_id, 'type': 'dh'}
    pub_payload = json.dumps(data)
    client.publish("newDeviceResponse", pub_payload, 1)

    #exchange key
    shared_key = private_key.exchange(peer_public_key)

  elif payload['type'] == 'ecdhe':
    #get peer public key from sent parameters
    peer_public_key = ec.EllipticCurvePublicNumbers(int(payload['x']), int(payload['y']), ec.SECP384R1()).public_key(default_backend())

    #generate own keys
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    
    #send the public data back to the IoT device
    data = {'x': public_key.public_numbers().x, 'y': public_key.public_numbers().y, 'id': device_id, 'type': 'ecdhe'}
    pub_payload = json.dumps(data)
    client.publish("newDeviceResponse", pub_payload, 1)

    #exchange key
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
  
  else:
    print("Something went wrong...")
  print("derive")
  #derive key from shared key
  derived_key = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(bytes.fromhex(devices[device_id]['master_key']))

  print("generate")
  #generate actual key used for encryption using HMAC and the master key
  h = hmac.HMAC(derived_key, hashes.SHA384(), backend=default_backend())
  h.update(shared_key)
  derived_key = h.finalize()[:32]

  print("store")
  #store encryption key
  devices[device_id].update({"derived_key": derived_key})
  print("A new key was generated for the device " + device_id + ".")

#decrypt received data
def decrypt(client, payload, topic):
  device_id = payload['id']
  print("Received encrypted message from topic " + topic + ": " + payload['encrypted_data'])
  
  #decrypt message using the correct encryption type
  #encryption type is sent everytime because that way the device could change the encryption for every message without problems
  if payload['encryption'] == 'fernet':
    #get bytes
    encrypted_data = payload['encrypted_data'].encode() 

    #get stored encryption key and create cipher
    key = base64.urlsafe_b64encode(devices[device_id]['derived_key']) 
    f = Fernet(key)

    #decrypt
    message = f.decrypt(encrypted_data)

  elif payload['encryption'] == 'aead':
    #get stored encryption key
    key = devices[device_id]['derived_key']

    #get nonce, additional data and encrypted message
    aad = bytes.fromhex(payload['aad'])
    nonce = bytes.fromhex(payload['nonce'])
    encrypted_data = bytes.fromhex(payload['encrypted_data'])

    #create cipher
    #ChaCha20Poly1305 was used here
    chacha = ChaCha20Poly1305(key)

    #decrypt message
    message = chacha.decrypt(nonce, encrypted_data, aad)
    
  else:
    print('unknown encryption')
    return 0

  print("The decrypted message received from topic " + topic + " is: " + str(message.hex()))

#simulate actual platform
def runDevice():
  global master_key

  #connect to MQTT broker
  client = mqtt.Client()
  client.on_connect = on_connect
  client.on_message = on_message
  client.username_pw_set("try","try")
  client.connect("broker.shiftr.io", 1883, 60)

  # Inicia una nueva hebra
  client.loop_start()
  time.sleep(1) #so the output is displayed in the correct order

  #let user choose what to do
  while 1:
    seconds = 1
    print("What do you want to do?\n 1 Listen for new messsages\n 2 List registered devices\n 3 Remove device\n 4 Register a new device")
    try:
      choice1=int(input())
    except ValueError:
      print("This is not a whole number.")
      continue
    
    if choice1 == 1:
      try:
        seconds = int(input("For how many seconds? "))
      except ValueError:
        print("This is not a whole number.")
        continue
      print("Listening...")
    elif choice1 == 2:
      for key in devices.keys():
        print("Device " + key)
      print("\n")
    elif choice1 == 3:
      device = input("Enter the id of the device that should be removed: ")
      devices.pop(device , None)
    elif choice1 == 4:
      while True:
        print("Choose device type.\n 1 IoT device has neither input nor output (static master key)\n 2 IoT device has Input device\n 3 IoT device has output device\n")
        choice = input()
        if choice in ['1','2','3']:
          break

      if choice == '3':
        print("Enter the master key (as a hex number).")
        master_key = input()

      elif choice == '2':
        master_key = str(os.urandom(32).hex())
        print("Master key : " + master_key)
        print("Enter this master key at the IoT device to enable authentication at the beginning of the connection.")
      else:
        master_key = 'a51409c2ef907c1c4b82745d31f6677e2b80f32e705b122fdfc9a6f17aaa25af'

      input("\nWaiting for authentication.\nPress Enter when device was authenticated and encryption was selected at IoT device.\n")

    else:
      print("That's not a valid choice.")
      continue
    time.sleep(seconds)

#get and store authenticated id of IoT device
def authenticate(payload, client):
  #get HMAC
  h = hmac.HMAC(bytes.fromhex(master_key), hashes.SHA256(), backend=default_backend())
  h.update(bytes.fromhex(payload['id']))

  #compare computed HMAC to sent HMAC
  h.verify(bytes.fromhex(payload['hmac']))

  #store the device id if both HMACs are the same
  devices.update({payload['id']: {'master_key': master_key}})
  print("Device " + payload['id'] + "is authenticated and added to registered devices")

  #TODO: choose topic for communication
  
  #channel = input("\nSelect the topic for this device: ")
  #devices[payload['id']].update({'topic': channel})

  #h2 = hmac.HMAC(bytes.fromhex(master_key), hashes.SHA256(), backend=default_backend())
  #h2.update(devices[payload['id']]['topic'].decode())
  #channel_hash = h2.finalize()
  
  #dic = {'channel': devices[payload['id']]['topic'], 'hmac': str(channel_hash.hex())}
  #print("Topic of device " + payload['id'] + "is now set to " + channel + ".")
  #message = json.dumps(dic)

  #client.publish("authenticateResponse", message, 1)


#global master key if IoT device has no input and no output
master_key = 'a51409c2ef907c1c4b82745d31f6677e2b80f32e705b122fdfc9a6f17aaa25af'

#global database for platform in form of a dictionary
devices = dict()

#start simulation of platform
runDevice()


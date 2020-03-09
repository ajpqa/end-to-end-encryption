#import paho-mqtt # https://python.org/pypi/paho-mqtt
import paho.mqtt.client as mqtt
import json

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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.serialization import load_pem_parameters
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
  if msg.topic == 'newDevice':
    payload = json.loads(msg.payload)
    newDevice(client, payload)
  elif msg.topic == 'authentication':
    payload = json.loads(msg.payload)
    authenticate(payload, client)
  else:
    print("got a new message")
    payload = json.loads(msg.payload)
    decrypt(client, payload)

def newDevice(client, payload):
  g = int(payload["g"])
  p = int(payload["p"])
  y = int(payload["public_key"])
  device_id = payload["id"]

  if device_id not in devices.keys():
    print("Device needs to authenticate")
    return 1 


  pn = dh.DHParameterNumbers(p, g)
  parameters = pn.parameters(default_backend())
  peer_public_numbers = dh.DHPublicNumbers(y, pn)
  peer_public_key = peer_public_numbers.public_key(default_backend())

  private_key = parameters.generate_private_key()

  public_key = private_key.public_key()
  #print("Esta es tu clave pública: %d"%public_key.public_numbers().y)

  data = {'g': parameters.parameter_numbers().g, 'p': parameters.parameter_numbers().p, 'public_key': public_key.public_numbers().y}
  pub_payload = json.dumps(data)

  client.publish("newDeviceResponse", pub_payload, 1)

  #print("published" + pub_payload)

  shared_key = private_key.exchange(peer_public_key)

  derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)

  #print("Clave calculada por mi = %s\n"%derived_key.hex())
  devices[device_id].update({"derived_key": derived_key})

def decrypt(client, payload):
  device_id = payload['id']
  
  if payload['encryption'] == 'fernet':
    print("fernet")
    encrypted_data = payload['encrypted_data'].encode()
    key = base64.urlsafe_b64encode(devices[device_id]['derived_key'])
    f = Fernet(key)
    message = f.decrypt(encrypted_data)

  elif payload['encryption'] == 'aead':
    print("aead")
    key = devices[device_id]['derived_key']
    aad = bytes.fromhex(payload['aad'])
    nonce = bytes.fromhex(payload['nonce'])
    encrypted_data = bytes.fromhex(payload['encrypted_data'])
    #print("aad and nonce")
    chacha = ChaCha20Poly1305(key)
    #print("cipher")
    message = chacha.decrypt(nonce, encrypted_data, aad)
    
  else:
    print('unknown encryption')
    return 0

  print(str(message.hex()))

def runDevice():
  global master_key
  client = mqtt.Client()
  client.on_connect = on_connect
  client.on_message = on_message

  client.username_pw_set("try","try")

  client.connect("broker.shiftr.io", 1883, 60)

  # Inicia una nueva hebra
  client.loop_start()

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
      print(devices.keys())
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
        master_key = str(os.urandom(16).hex())
        print("Master key : " + master_key)
        print("Enter this master key at the IoT device to enable authentication at the beginning of the connection.")

      input("\nWaiting for authentication.\nPress Enter when device was authenticated and encryption was selected at IoT device.\n")

    else:
      print("That's not a valid choice.")
      continue
    time.sleep(seconds)

def authenticate(payload, client):
  h = hmac.HMAC(bytes.fromhex(master_key), hashes.SHA256(), backend=default_backend())
  h.update(bytes.fromhex(payload['id']))

  h.verify(bytes.fromhex(payload['hmac']))

  devices.update({payload['id']: {}})
  print("Device " + payload['id'] + "is authenticated and added to registered devices")
  
  #channel = input("\nSelect the topic for this device: ")
  #devices[payload['id']].update({'topic': channel})

  #h2 = hmac.HMAC(bytes.fromhex(master_key), hashes.SHA256(), backend=default_backend())
  #h2.update(devices[payload['id']]['topic'].decode())
  #channel_hash = h2.finalize()
  
  #dic = {'channel': devices[payload['id']]['topic'], 'hmac': str(channel_hash.hex())}
  #print("Topic of device " + payload['id'] + "is now set to " + channel + ".")
  #message = json.dumps(dic)

  #client.publish("authenticateResponse", message, 1)

master_key = '03574e16832140423cc63f5ba02cd2063d3c28e41a497aa471e75fb640ca3e1c'

devices = dict()
runDevice()






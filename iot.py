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

import time

import json

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("adios")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

    if msg.topic == "newDeviceResponse":
      payload = json.loads(msg.payload)
      getSharedKey(payload)

def establishConnection(client):
    global keys
    
    backend = default_backend()
    parameters = dh.generate_parameters(generator=2, key_size=512,backend=default_backend())
    params_pem = parameters.parameter_bytes(Encoding.PEM,ParameterFormat.PKCS3)
    print("Parámetros PKCS3: ")
    print(params_pem.decode("utf-8"))
    print("Parámetros Número: ")
    print("g (alpha) = %d"%parameters.parameter_numbers().g)
    print("p = %d\n"%parameters.parameter_numbers().p) 

    #Generate private keys.
    private_key = parameters.generate_private_key()
    a_public_key = private_key.public_key()
    print("Esta es tu clave pública: %d"%a_public_key.public_numbers().y)

    data = {'g': parameters.parameter_numbers().g, 'p': parameters.parameter_numbers().p, 'public_key': a_public_key.public_numbers().y}

    payload = json.dumps(data)
    print(payload)

    client.subscribe("newDeviceResponse")
    client.publish("newDevice", payload, 1)

    keys.update({'private_key': private_key})

def getSharedKey(payload):
    global keys

    g = int(payload["g"])
    p = int(payload["p"])
    y = int(payload["public_key"])

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())


    shared_key = keys['private_key'].exchange(peer_public_key)
    print("Clave calculada por mi = %s\n"%shared_key.hex())

    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)

    keys.update({'derived_key': derived_key})
    print(keys)
   
keys = dict()

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.username_pw_set("try","try")

client.connect("broker.shiftr.io", 1883, 60)

# Si quiero que esté escuchando para siempre:
# client.loop_forever()
# http://www.steves-internet-guide.com/loop-python-mqtt-client/

# Inicia una nueva hebra
client.loop_start()

establishConnection(client)
print(keys)
#print("Clave calculada por mi = %s\n"%keys['shared_key'].hex())

while 'derived_key' not in keys:
  print("waiting for derived key")
  time.sleep(1)

key = base64.urlsafe_b64encode(keys['derived_key'])
f = Fernet(key)


while 1:
    # Publish a message every second
    #client.publish("hola", "Hello World", 1)

    message = f.encrypt(b'Test message')
    print("message: " + str(message))

    client.publish("messages", message, 1)
    
    time.sleep(1)


# También se puede conectar y enviar en una linea https://www.eclipse.org/paho/clients/python/docs/#single

# Y conectar y bloquear para leer una sola vez en una sola linea https://www.eclipse.org/paho/clients/python/docs/#simple


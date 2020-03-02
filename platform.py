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

import time

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("newDevice")
    client.subscribe("removeDevice")
    client.subscribe("messages")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    if msg.topic == 'newDevice':
      print("start DH and add new device")
      payload = json.loads(msg.payload)
      newDevice(client, payload)
      print("done")
    elif msg.topic == 'removeDevice':
      keys.pop(msg.payload.id, 0)
    elif msg.topic == 'messages':
      print("got a new message")
      decrypt(client, msg.payload)
    else:
      print(msg.topic+" "+str(msg.payload))

def newDevice(client, payload):
    print("aqui")
    g = int(payload["g"])
    p = int(payload["p"])
    y = int(payload["public_key"])

    #print("g: " + str(g))
    #print("p: " + str(p))
    #print("y: " + str(y))

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())

    private_key = parameters.generate_private_key()

    public_key = private_key.public_key()
    print("Esta es tu clave pública: %d"%public_key.public_numbers().y)

    data = {'g': parameters.parameter_numbers().g, 'p': parameters.parameter_numbers().p, 'public_key': public_key.public_numbers().y}
    pub_payload = json.dumps(data)

    client.publish("newDeviceResponse", pub_payload, 1)

    print("published" + pub_payload)

    shared_key = private_key.exchange(peer_public_key)

    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)

    print("Clave calculada por mi = %s\n"%derived_key.hex())
    keys.update({"derived_key": derived_key})

def decrypt(client, payload):
    key = base64.urlsafe_b64encode(keys['derived_key'])
    f = Fernet(key)
    message = f.decrypt(payload)
    print(str(message))



keys = dict()

device_id = urandom(16)

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

while 1:
    time.sleep(1)

# También se puede conectar y enviar en una linea https://www.eclipse.org/paho/clients/python/docs/#single

# Y conectar y bloquear para leer una sola vez en una sola linea https://www.eclipse.org/paho/clients/python/docs/#simple

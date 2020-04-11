-key rotation happens every 30 seconds if there are no messages in the queue (can be changed in the code)
-messages are sent every 5 seconds (can be changed in the code)
-code contains comments to explain functionality

fulfilled tasks:
----------------

UX: (2)
	CLI with different parameters to select the type of device, encryption and key exchange method
	platform has options to register, list or delete devices or just listen to incoming messages
	after set-up of IoT device just the number of to be sent messages can be chosen, everything else happens in the background

Key Management: (3)
	master keys are only used for authentication and generating the encryption keys using HMAC
	encryption keys are rotated (standard every 30 seconds)
	different devices can have different master keys (through different types of devices) but once it's set, the master key of a device can't be changed

Symmetric Crypto: (3)
	different devices can use different encryptions
	Fernet and AEAD algorithm ChaCha20Poly1305 are supported

Asymmetric Crypto: (3)
	different devices can use different key exchange algorithms
	HMAC authenticated DH and ECDH with ephemeral keys are supported

IoT Platform Features: (1-2) 
	new devices can be registered, listed or removed
 	all devices use the same topics

Links to the written code:
--------------------------

IoT device: 	https://repl.it/@gmmeine12/iotDevice
Platform: 	https://repl.it/@gmmeine12/platform

Team:
-----

Tim Reiprich
Ali Haider

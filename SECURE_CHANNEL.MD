# Secure Channel

## Overview
A Secure Channel must be established to allow communication between the applet and the client. This secure channel has
the concept of pairing with multiple devices (how many clients can be paired at the same time is defined by the applet).
The SecureChannel guarantees protection from snooping, MITM, replay attacks and provides message integrity and 
authentication for each APDU.

A short description of establishing a session is as follows

1. The client selects the application on card. The application responds with a public EC key.
2. The client sends an OPEN SECURE CHANNEL command with its public key. The EC-DH algorithm is used by both parties to 
   generate a shared 256-bit secret (more details below).
3. The generated secret is used as an AES key to encrypt all further communication. CBC mode is used with a random IV
generated for each APDU and prepended to the APDU payload. Both command and responses are encrypted.
4. The client sends a MUTUALLY AUTHENTICATE command to verify that the keys are matching and thus the secure channel is
successfully established.

The EC keyset used by the card for the EC-DH algorithm is generated on-card on applet installation and is not used
for anything else. The EC keyset used by the client is generated every time a new secure channel session must be 
opened.

## APDU format

### OPEN SECURE CHANNEL

* CLA = 0x80
* INS = 0x10
* P1 = the pairing index
* P2 = 0x00
* Data = An EC-256 public key on the SECP256k1 curve encoded as an uncompressed point.
* Response Data = A 256-bit salt and a 128-bit seed IV
* Response SW = 0x9000 on success, 0x6A86 if P1 is invalid, 0x6A80 if the data is not a public key

This APDU is the first step to establish a Secure Channel session. A session is aborted when the application is 
deselected, either directly or because of a card reset/tear.

The card generates a random 256-bit salt which is sent to the client. Both the client and the card do the following
for key derivation

1. Use their private key and the counterpart public key to generate a secret using the EC-DH algorithm.
2. The generated secret, the pairing key and the salt are concatenated and the SHA-512 of the concatenated value is 
   calculated.
3. The output of the SHA-512 algorithm is split in two parts of 256-bit. The first part is used as the encryption key
and the second part is used as the MAC key for further communication.

The seed IV is used by the client as the IV for the next encrypted APDU.

### MUTUALLY AUTHENTICATE

* CLA = 0x80
* INS = 0x11
* P1 = 0x00
* P2 = 0x00
* Data = 256-bit random number
* Response Data = 256-bit random number
* Response SW = 0x9000 on success, 0x6985 if the previous successfully executed APDU was not OPEN SECURE CHANNEL, 0x6982
if authentication failed, 0x6A80 if the data is not exactly 64 bytes long

This APDU allows both parties to verify that the keys generated in the OPEN SECURE CHANNEL step are matching and thus
guarantee authentication of the counterpart. The data sent by both parties is a 256-bit random number The APDU data is 
sent encrypted with the keys generated in the OPEN SECURE CHANNEL step. Each party must verify the MAC of the received
APDU. If the MAC can be verified, it means that both parties are using the same keys. Only after this step has been 
executed the secure channel can be considered to be open and other commands can be sent. If the authentication fails 
the card must respond with 0x6982. In this case the OPEN SECURE CHANNEL command must be repeated to generate new keys. 
This greatly slows down brute-force attempts.

### PAIR

* CLA = 0x80
* INS = 0x12
* P1 = pairing phase
* P2 = 0x00
* Data = see below
* Response Data = see below
* Response SW = 0x9000 on success, 0x6A80 if the data is in the wrong format, 0x6982 if client cryptogram verification 
fails, 0x6A84 if all available pairing slot are taken, 0x6A86 if P1 is invalid or is 0x01 but the first phase was not 
completed, 0x6985 if a secure channel is open

P1:
* 0x00: First step
* 0x01: Final step

Data:
* On first step: a 256-bit random client challenge
* On second step: the client cryptogram as SHA-256(shared secret, card challenge)

Response Data:
* On first step: the card cryptogram as SHA-256(shared secret, client challenge) followed by a 256-bit card challenge
* On second step: the pairing index followed by a 256-bit salt

This APDU is sent to pair a client. Pairing is performed with two commands which must be sent immediately one after the
other. 

In the first phase the client sends a random challenge to the card. The card replies with the SHA-256 hash of the
challenge and the shared secret followed by its random challenge. The client is thus able to authenticate the card by
verifying the card cryptogram (since the client can generate the same and verify that it matches).

In the second phase the client sends the client cryptogram which is the SHA-256 hash of the shared secret and the card
challenge. The card verifies the cryptogram and thus authenticates the client. On success the card generates a random
256-bit salt which is appended to the shared secret. The SHA-256 hash of the concatenated value is stored in the fist
available pairing slot and will be further used to derive session keys. The card responds with the pairing index (which
the client must send in all OPEN SECURE CHANNEL commands) and the salt used to generate the key, so that the client can
generate and store the same key.

The shared secret is a 256-bit value which must be be known to both parts being paired. The exact means of how this
happens depend on the specific applet.

### UNPAIR

* CLA = 0x80
* INS = 0x13
* P1 = the index to unpair
* P2 = 0x00
* Response SW = 0x9000 on success, 0x6985 if security conditions are not met, 0x6A86 if the index is higher than the
  highest possible pairing index.

This APDU is sent to unpair a client. An existing secure channel session must be open. The application implementing this
protocol may apply additional restrictions, such as the verification of a user PIN. On success the pairing slot at the 
given index will be freed and will be made available to pair other clients. If the index is already free nothing will 
happen.

### Encrypted APDUs

After a successful OPEN SECURE CHANNEL command all communication between card and client is encrypted. Note that only 
the data fields of C-APDU and R-APDU are encrypted, which means that CLA, INS, P1, P2 for C-APDU and SW1SW2 for R-APDU 
are plaintext. This means no sensitive data should be sent in these parameters. Additionally a MAC is calculated for the
entire APDU, including the unencrypted fields.

To encrypt the data both the card and the client do the following:

1. The data is padded using the ISO/IEC 9797-1 Method 2 algorithm.
2. The data is encrypted using AES in CBC mode using the session key.
3. An AES CBC-MAC is calculated over the entire APDU data
4. The data field of the APDU is set to the MAC followed by the encrypted data.

To decrypt the data both the card and the client do the following:

1. The first 16 bytes of the APDU data are the MAC to be verified
2. The remaining data is decrypted using AES in CBC mode using the session key.
3. The padding is removed.

The IV used for the encryption is the last seen MAC from the counterpart. This optimizes the number
of transmitted bytes and guarantees protection from replay attacks. For the MAC generation, a zero IV is always used.

MAC generation for C-APDUs is calculated on the concatenation of CLA INS P1 P2 LC 00 00 00 00 00 00 00 00 00 00 00 and
the encrypted data field. The 11-byte long padding does not become part of the data field and does not affect LC

MAC generation fo R-APDUs is calculated on the concatenation of Lr SW1 SW2 00 00 00 00 00 00 00 00 00 00 00 00 00 and
the encrypted data field. The 13-byte long padding does not become part of the response field. Lr is the length of the
encrypted response data field and is not transmitted.

Because AES in CBC mode requires the data field length in bytes to be a multiple of 16, the maximum effective APDU
size becomes 240 bytes. Of these 16 bytes are used for the MAC and minimum of 1 byte for padding, making the maximum
payload size in a single APDU 223 bytes, meaning about a 13,5% overhead.

### Error conditions

1. If a sensitive command is received without an active Secure Channel, the card shall respond with SW 0x6985 (
SW_CONDITIONS_NOT_SATISFIED)
2. If a MAC cannot be verified the card shall respond 0x6982 and the Secure Channel must be closed
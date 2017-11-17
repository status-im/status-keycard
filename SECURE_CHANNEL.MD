# Secure Channel

## Overview
A Secure Channel must be established to allow communication between the applet and the client. This secure channel has
the concept of pairing with multiple devices (how many clients can be paired at the same time is defined by the applet).
The SecureChannel guarantees protection from snooping, MITM and replay attacks across different sessions, since the way
a session is established makes it impossible to generate the same session keys twice. Since a session is automatically
aborted as soon as power is lost or the application is reselected, it not possible to resume the last session and
perform replay attacks there.

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
* Response Data = A 256-bit salt
* Response SW = 0x9000 on success, 0x6A86 if P1 is invalid

This APDU is the first step to establish a Secure Channel session. A session is aborted when the application is deselected,
either directly or because of a card reset/tear. This APDU and its response are not encrypted.

The card generates a random 256-bit salt which is sent to the client. Both the client and the card do the following
for key derivation

1. Use their private key and the counterpart public key to generate a secret using the EC-DH algorithm.
2. The generated secret, he pairing key and the salt are concatenated and the SHA-256 of the concatenated value is 
   calculated.
3. The output of the SHA-256 algorithm is used as the AES key for further communication.

### MUTUALLY AUTHENTICATE

* CLA = 0x80
* INS = 0x11
* P1 = 0x00
* P2 = 0x00
* Data = 256-bit random number and its SHA-256 hash
* Response Data = 256-bit random number and its SHA-256 hash
* Response SW = 0x9000 on success, 0x6985 if the previous successfully executed APDU was not OPEN SECURE CHANNEL, 0x6982
if authentication failed, 0x6A80 if the data is not exactly 64 bytes long

This APDU allows both parties to verify that the keys generated in the OPEN SECURE CHANNEL step are matching and thus
guarantee authentication of the counterpart. The data sent by both parties is a 32-bit random number followed by its own
SHA-256 hash. The APDU data is sent encrypted with the keys generated in the OPEN SECURE CHANNEL step. Each party must
verify that the hash indeed matches the value sent. If this is true, then the decryption was correct, meaning that the
keys are matching. Only after this step has been executed the secure channel can be considered to be open and other 
commands can be sent.

### PAIR

* CLA = 0x80
* INS = 0x12
* P1 = pairing phase
* P2 = 0x00
* Data = see below
* Response Data = see below
* Response SW = 0x9000 on success, 0x6A80 if the data are in the wrong format, 0x6982 if client cryptogram verification 
fails, 0x6A84 if all available pairing slot are taken, 0x6A86 if P1 is invalid or is 0x01 but the first phase was not 
completed

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
verifying the card cryptogram (since the client can generate the same and verify that is matches).

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
* Data = the same index as in P1
* Response SW = 0x9000 on success, 0x6985 if security conditions are not met, 0x6A86 if the index is higher than the
  highest possible pairing index.

This APDU is sent to unpair a client. An existing secure channel session must be open. The application implementing this
protocol may apply additional restrictions, such as the verification of a user PIN. The reason to repeat P1 in the data
field is to verify that the client indeed performed authentication and has the correct session keys. On success the
pairing slot at the given index will be freed and will be made available to pair other clients. If the index is already
free nothing will happen.

### Encrypted APDUs

After a SecureChannel session has been established all communication between card and client is encrypted. Note
that only the data fields of C-APDU and R-APDU are encrypted, which means that CLA, INS, P1, P2 for C-APDU and SW1SW2 for
R-APDU are plaintext. This means no sensitive data should be sent in these parameters.

To encrypt the data both the card and the client do the following:

1. The data is padded using the ISO/IEC 9797-1 Method 2 algorithm.
2. A random IV is generated.
3. The data is encrypted using AES in CBC mode using the session key.
4. The data field of the APDU is set to the IV followed by the encrypted data.

To decrypt the data both the card and the client do the following:

1. The first 16 bytes of the APDU are treated as IV.
2. The remaining data is decrypted using AES in CBC mode using the session key.
3. The padding is removed.

Because AES in CBC mode requires the data field length in bytes to be a multiple of 16, the maximum effective APDU
size becomes 240 bytes. Of these 16 bytes are used for the IV and minimum of 1 byte for padding, making the maximum
payload size in a single APDU 223 bytes, meaning about a 13,5% overhead.

### Error conditions

1. If a sensitive command is received without an active Secure Channel, the card shall respond with SW 0x6985 (
SW_CONDITIONS_NOT_SATISFIED)
2. If a Secure Channel is established but a sensitive command is received plaintext, the card shall respond with
SW 0x6982 (SW_SECURITY_STATUS_NOT_SATISFIED). The error 0x6F00 (SW_UNKNOWN) is also acceptable in this case.
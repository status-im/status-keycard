# Secure Channel

## Overview
A Secure Channel must be established to allow communication between the applet and the client. The reason for using
a secure channel is to avoid traffic snooping. What we achieve with the secure channel below is only secrecy, not
authentication. Authentication would require either a set of pre-shared keys or the usage of certificates. In particular,
it does not protect from MITM attacks. If the risk of such attacks exists, protection should be set up in a different
layer or the protocol must be extended for mutual authentication.

A short description of the protocol is as follows

1. The client selects the application on card. The application responds with a public EC key.
2. The client sends an OPEN SECURE CHANNEL command with its public key. The EC-DH algorithm is used by both parties to
generate a shared 256-bit secret (more details below).
3. The generated secret is used as an AES key to encrypt all further communication. CBC mode is used with a random IV
generated for each APDU and prepended to the APDU payload. Both command and responses are encrypted.

The EC keyset used by the card for the EC-DH algorithm is generated on-card on applet installation and is not used
for anything else. The EC keyset used by the client is generated every time a new secure channel session must be 
opened.

## APDU format

### OPEN SECURE CHANNEL

This APDU is sent to establish a Secure Channel session. A session is aborted when the application is deselected,
either directly or because of a card reset/tear. This APDU and its response are not encrypted.

* CLA = 0x80
* INS = 0x10
* P1 = 0x00
* P2 = 0x00
* Data = An EC-256 public key on the SECP256k1 curve encoded as an uncompressed point.
* Response Data = A 256-bit salt
* Response SW = 0x9000

The card generates a random 256-bit salt which is sent to the client. Both the client and the card do the following
for key derivation

1. Use their private key and the counterpart public key to generate a secret using the EC-DH algorithm. The JavaCard
EC_SVDP_DH implementation actually output the SHA-1 of the plain secret, so the client must do the same.
2. The generated secret and the salt are concatenated and their SHA-256 is calculated.
3. The output of the SHA-256 algorithm is used as the AES key for further communication.

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

### Error conditions

1. If a sensitive command is received without an active Secure Channel, the card shall respond with SW 0x6985 (
SW_CONDITIONS_NOT_SATISFIED)

2. If a Secure Channel is established but a sensitive command is received plaintext, the card shall respond with
SW 0x6982 (SW_SECURITY_STATUS_NOT_SATISFIED). The error 0x6F00 (SW_UNKNOWN) is also acceptable in this case.
# Status Wallet Application

## Overview

This application allows signing of transactions using ECDSA with a keyset stored on card. The keys are defined on the
SECP256k1 curve. Signing is available only after PIN authentication.

The keyset used for signing is generated externally and loaded on card. This is also only available after PIN 
authentication.

Before any application command is processed, a Secure Channel session must be established as specified in the 
[SECURE_CHANNEL.MD](SECURE_CHANNEL.MD) document.

## PIN

During installation the user's PIN is set to 000000 (six times zero). The PIN length is fixed at 6 digits. After 3 
failed authentication attempts the PIN is blocked and authentication is not possible anymore. A blocked PIN can be 
replaced and unblocked using a PUK. The PUK is a 12-digit number, unique for each installation and is generated off-card 
and passed as an installation parameter to the applet according to the JavaCard specifications. After 5 failed attempts 
to unblock the applet using the PUK, the PUK is blocked, meaning the the wallet is lost.

After authentication, the user remains authenticated until the application is either deselected or the card is reset.
Authentication with PIN is a requirement for most commands to succeed.

The PIN can be changed by the user after authentication.

## Keys & Signature

The application allows loading and replacing of a single EC keyset, defined on the SECP256k1 curve. The keyset can contain
a 32-byte chain code to further derive keys according to the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) 
specifications. This keyset is used to sign transactions. When the applet is first installed, no keyset is available so 
signing will fail. It is necessary to first load the keyset in order for the application to be fully operational.

Signing of transactions is done by uploading the data in blocks no larger than 255 bytes (including the overhead caused
by the Secure Channel). Segmentation must be handled at the application protocol. Another option is to sign the hash
of the transaction, with the hash being calculated off-card. Signing generally requires the PIN to be authenticated,
however the user can set a special key path which requires no authentication.

## APDUs

These are the commands supported by the application. When a command has a precondition clause and these are not met the
SW 0x6985 is returned. All tagged data structures are encoded in the [BER-TLV format](http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_annex-d.aspx) 

### SELECT

* CLA = 0x00
* INS = 0xA4
* P1 = 0x04
* P2 = 0x00
* Data = 53746174757357616C6C6574417070 (hex)
* Response = Application Info Template

Response Data format:
- Tag 0xA4 = Application Info Template
 - Tag 0x4F = Instance UID (16 bytes)
 - Tag 0x80 = ECC public Key

The SELECT command is documented in the ISO 7816-4 specifications and is used to select the application on the card,
making it the active one. The data field is the AID of the application. The response is the Application Info template
which contains the instance UID (which can be used by the client to keep track of multiple cards) and the public key 
which must be used by the client to establish the Secure Channel.

### OPEN SECURE CHANNEL

The OPEN SECURE CHANNEL command is as specified in the [SECURE_CHANNEL.MD](SECURE_CHANNEL.MD).

### MUTUALLY AUTHENTICATE

The MUTUALLY AUTHENTICATE command is as specified in the [SECURE_CHANNEL.MD](SECURE_CHANNEL.MD).

### PAIR

The PAIR command is as specified in the [SECURE_CHANNEL.MD](SECURE_CHANNEL.MD). The shared secret is the SHA-256 of the
PUK.

### UNPAIR

The UNPAIR command is as specified in the [SECURE_CHANNEL.MD](SECURE_CHANNEL.MD). The user PIN must be verified for the
command to work.

### GET STATUS

* CLA = 0x80
* INS = 0xF2
* P1 = 0x00 for application status, 0x01 for key path status
* P2 = 0x00
* Response SW = 0x9000 on success, 0x6A86 on undefined P1
* Response Data = Application Status Template or Key Path
* Preconditions: Secure Channel must be opened, if Key Path is required then the card must not be in the  middle of a 
derivation session

Response Data format:
if P1 = 0x00:
- Tag 0xA3 = Application Status Template
  - Tag 0x02 = PIN retry count (1 byte)
  - Tag 0x02 = PUK retry count (1 byte)
  - Tag 0x01 = 0 if key is not initialized, 1 otherwise
  - Tag 0x01 = 1 if public key derivation is supported, 0 otherwise

if P1 = 0x01
- a sequence of 32-bit numbers indicating the current key path. Empty if master key is selected.

### VERIFY PIN

* CLA = 0x80
* INS = 0x20
* P1 = 0x00
* P2 = 0x00
* Data = the PIN to be verified
* Response SW = 0x9000 on success, 0x63CX on failure, where X is the number of attempt remaining
* Preconditions: Secure Channel must be opened

Used to verify the user PIN. On correct PIN entry the card returns 0x9000, the retry counter is reset and the PIN is
marked as authenticated for the entire session (until the application is deselected or the card reset/teared). On
error, the number of remaining retries is decreased and the SW 0x63CX, where X is the number of available retries is
returned. When the number of remaining retries reaches 0 the PIN is blocked. When the PIN is blocked this command
always returns 0x63C0, even if the PIN is inserted correctly.

### CHANGE PIN

* CLA = 0x80
* INS = 0x21
* P1 = 0x00
* P2 = 0x00
* Data = the new PIN
* Response SW = 0x9000 on success, 0x6A80 if the PIN format is invalid
* Preconditions: Secure Channel must be opened, user PIN must be verified

Used to change the user PIN. The new PIN must be composed of exactly 6 numeric digits. Should this be not the case,
the code 0x6A80 is returned. If the conditions match, the user PIN is updated and authenticated for the rest of
the session. The no-error SW 0x9000 is returned.

### UNBLOCK PIN

* CLA = 0x80
* INS = 0x22
* P1 = 0x00
* P2 = 0x00
* Data = the PUK followed by the new PIN
* Response SW = 0x9000 on success, 0x6A80 if the format is invalid
* Preconditions: Secure Channel must be opened, user PIN must be blocked

Used to unblock the user PIN. The data field must contain exactly 18 numeric digits, otherwise SW 0x6A80 is returned. 
The first 12 digits are the PUK and the last 6 are the new PIN. If the PUK is correct the PIN is changed to the supplied 
one, it is unblocked and authenticated for the rest of the session. The status code 0x9000 is returned. When the PUK is 
wrong, the number of remaining retries is decreased and the SW 0x63CX, where X is the number of available retries is
returned. When the number of remaining retries reaches 0 the PUK is blocked. When the PUK is blocked this command
always returns 0x63C0, even if the PUK is inserted correctly. In this case the wallet is effectively lost.

### LOAD KEY

* CLA = 0x80
* INS = 0xD0
* P1 = key type
* P2 = 0x00
* Data = the key data
* Response SW = 0x9000 on success, 0x6A80 if the format is invalid, 0x6A86 if P1 is invalid, 0x6A81 if public key
  derivation is not supported and the public key is omitted
* Preconditions: Secure Channel must be opened, user PIN must be verified

P1:
* 0x01 = ECC SECP256k1 keypair
* 0x02 = ECC SECP256k1 extended keypair
* 0x03 = Binary seed as defined in [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

Data:

If P1 is 0x01 or 0x02
- Tag 0xA1 = keypair template
  - Tag 0x80 = ECC public key component (can be omitted if public key derivation is supported)
  - Tag 0x81 = ECC private key component
  - Tag 0x82 = chain code (if P1=0x02)
  
If P1 is 0x03 a 64 byte sequence generated according to the BIP39 specifications is expected. The master key will be
generated according to the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) specifications. This
is only supported if the hardware supports public key derivation.

This command is used to load or replace the keypair used for signing on the card. This command always aborts open
signing sessions, if any. Unless a DERIVE KEY is sent, a subsequent SIGN command will use this keypair for signature.

### DERIVE KEY

* CLA = 0x80
* INS = 0xD1
* P1 = derivation options
* P2 = assisted derivation phase
* Data = a sequence of 32-bit integers (most significant byte first). Empty if the master key must be used. On assisted
         derivation contains a public key when P2 = 0x02.
* Response SW = 0x9000 on success, 0x6A80 if the format is invalid, 0x6A81 if public key derivation is not supported and
  bit 0 of P1 is set, 0x6A86 if P2 = 0x01 and bit 0 of P1 is not set, 0x6984 if one of the components in the path
  generates an invalid key, 0x6B00 if derivation from parent keys is selected but no valid parent key is cached.
* Response Data = On assisted derivation and P2 = 0x01 the key derivation template. Empty otherwise.
* Preconditions: Secure Channel must be opened, user PIN must be verified (if no PIN-less key is defined), an extended 
keyset must be loaded

This command is used before a signing session to generate a private key according to the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
specifications. This command always aborts open signing sessions, if any. The generated key is used for all subsequent 
SIGN sessions. Because JavaCard does not offer native EC point multiplication before version 3.0.5, there is an 
alternative mode of operation where the public key is partially derived off-card and loaded back on card. In this mode
of operation only 1 derivation step at the time can be completed and as such during assisted derivation the data can
contain a single 32-bit integer, instead of a sequence. The maximum depth of derivation from the master key is 10. Any
attempt to get deeper results in 0x6A80 being returned. The BIP32 specifications define a few checks which must be
performed on the derived keys. If these fail, the 0x6984 is returned and the invalid key is discarded. A client should
perform a GET STATUS command to get the actual current key path and resume derivation using a different path.

The ability to start derivation from the parent keys allows to more efficiently switch between children of the same key. 
Note however that only the immediate parent of the current key is cached so you cannot use this to go back in the 
hierarchy. If no valid parent key is available the status code 0x6B00 will be returned.

When loading the public key using assisted derivation the only valid P1/P2 combination is P1=0x81 and P2=0x01.

P1:
* bit 0 = if 0 derive autonomously (only works if public key derivation is supported), if 1 do assisted derivation
* bit 1-5 = reserved
* bit 7-6:
  - 00 derive from master keys
  - 01 derive from parent keys
  - 10 derive from current keys
  - 11 reserved

P2:
* 0x00 = data is a sequence of 32-bit integers
* 0x01 = data is a public key

Response Data format:
The signature is calculated over the SHA-256 hash of the message "STATUS KEY DERIVATION"

- Tag 0xA2 = key derivation template
  - Tag 0x83 = ECC Public Key X component
  - Tag 0x30 = ECDSA Signature
    - Tag 0x02 = R value
    - Tag 0x02 = S value

### GENERATE MNEMONIC

* CLA = 0x80
* INS = 0xD2
* P1 = checksum size (between 4 and 8)
* P2 = 0x00
* Response SW = 0x9000 on success. 0x6A86 if P1 is invalid.
* Response Data = a sequence of 16-bit integers (most significant byte first).
* Preconditions: Secure Channel must be opened

Used to generate a mnemonic according to the algorithm specified in [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). 
The returned data is a list of 16-byte integers which should be used as indexes in a wordlist to generate the 
human-readable mnemonic. Each integer can have a value from 0 to 2047.

### SIGN

* CLA = 0x80
* INS = 0xC0
* P1 = data type
* P2 = segment flag
* Data = the data to sign
* Response = if P2 indicates last segment, the public key and the signature are returned
* Response SW = 0x9000 on success, 0x6A86 if P2 is invalid
* Preconditions: Secure Channel must be opened, user PIN must be verified (or a PIN-less key must be active), a valid 
keypair must be loaded

P1:
* 0x00 = transaction data
* 0x01 = precomputed hash

P2:
* bit 0 = if 1 first block, if 0 other block
* bit 1-6 = reserved
* bit 7 = if 0 more blocks, if 1 last block

Response Data format:
- Tag 0xA0 = signature template
  - Tag 0x80 = ECC public key component
  - Tag 0x30 = ECDSA Signature
    - Tag 0x02 = R value
    - Tag 0x02 = S value

Used to sign transactions. Since the maximum short APDU size is 255 bytes the transaction must be segmented before
being sent if it is larger than that. The overhead from the Secure Channel must be also accounted for. When the last
segment is sent, the card returns the calculated signature. The signature is an ECDSA signature calculated over the
SHA-256 hash of the sent data or directly over the provided hash if P1 = 0x01.

The P2 parameter is used to manage the signing session and is treated as a bitmask. The rightmost bit indicates whether
this block is the first one (1) or not (0). On the first block the card resets the signature state. The leftmost bit
indicates whether this is the last block (1) or not (0). On the last block, the card generates and sends the signatures
to the client.

For example, if a signing session spans over 3 segments, the value of P2 will be respectively 0x01, 0x00, 0x80. If
the signing session is composed of a single session P2 will have the value of 0x81.

After a signature is generated, the next SIGN command must have the rightmost bit of P2 set, otherwise 0x6A86 will
be returned.

This segmentation scheme allows resuming signature sessions if other commands must be sent in between and at 
the same time avoid generating signatures over partial data, since both the first and the last block are marked.

On applet selection any pending signing session is aborted.

### SET PINLESS PATH

* CLA = 0x80
* INS = 0xC1
* P1 = 0x00
* P2 = 0x00
* Data = a sequence of 32-bit integers
* Response SW = 0x9000 on success, 0x6A80 if data is invalid
* Preconditions: Secure Channel must be opened, user PIN must be verified

Sets the given sequence of 32-bit integers as a PIN-less path. When the current derived key matches this path, SIGN
will work even if no PIN authentication has been performed. An empty sequence means that no PIN-less path is defined.

### EXPORT KEY

* CLA = 0x80
* INS = 0xC2
* P1 = key path index
* P2 = export options
* Response SW = 0x9000 on success, 0x6A86 if P1 or P2 are wrong
* Response Data = key pair template
* Preconditions: Secure Channel must be opened, user PIN must be verified, the current key path must match the one of
  the key selected through P1
  
P1:
0x00 = Any key
0x01 = Whisper key (m/1/1)

P2:
0x00 = private and public key
0x01 = public key only
  
Response Data format:
- Tag 0xA1 = keypair template
  - Tag 0x80 = ECC public key component
  - Tag 0x81 = ECC private key component (if P2=0x00)
  
This command exports the current public and private key if and only if the current key path matches the one of the key
selected by P1. P1 is only an index, the actual key path is stored immutably in the applet itself. At the moment only
the Whisper key (P1=0x01) can be exported and its key path is m/1/1. Other key paths could be added in the future, but
the last should remain as short as possible because of the security implications of revealing private keys to a possibly
compromised device. The current chain code is never exported to make it impossible to further derive keys off-card.

The special index 0x00 indicates any path, which means the current key will always be exported regardless of its actual
path. This works however only in combination with P2=0x01, so only the public key will be exported.

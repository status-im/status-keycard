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
Authentication with PIN is a requirement for all further commands to succeed.

The PIN can be changed by the user after authentication.

## Keys & Signature

The application allows loading a replacing of a single EC keyset, defined on the SECP256k1 curve. This keyset is used
to sign transactions. When the applet is first installed, no keyset is available so signing will fail. It is necessary
to first load the keyset in order for the application to be fully operational.

Signing of transactions is done by uploading the data in blocks no larger than 255 bytes (including the overhead caused
by the Secure Channel). Segmentation must be handled at the application protocol.

## APDUS

These are the commands supported by the application. When a command has a precondition clause and these are not met the
SW 0x6985 is returned.

### SELECT

* CLA = 0x00
* INS = 0xA4
* P1 = 0x04
* P2 = 0x00
* Data = 53746174757357616C6C6574417070 (hex)
* Response = The public key used to establish the SecureChannel

The SELECT command is documented in the ISO 7816-4 specifications and is used to select the application on the card,
making it the active one. The data field is the AID of the application. The response is the public key which must
be used by the client to establish the Secure Channel.

### OPEN SECURE CHANNEL

The OPEN SECURE CHANNEL command is as specified in the [SECURE_CHANNEL.MD](SECURE_CHANNEL.MD).

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
the code 0x6A80 is returned. If the conditions matches the user PIN is updated and authenticated for the rest of
the session. The no-error SW 0x9000 is returned.

### UNBLOCK PIN

* CLA = 0x80
* INS = 0x22
* P1 = 0x00
* P2 = 0x00
* Data = the PUK followed by the new PIN
* Response SW = 0x9000 on success, 0x6A80 if the format is invalid
* Preconditions: Secure Channel must be opened, user PIN must be blocked

Used to unblock the user PIN. The data field must contain exactly 18 numeric digits, otherwise SW 0x6A80 is returned. The first 12 digits are the PUK
and the last 6 are the new PIN. If the PUK is correct the PIN is changed to the supplied one, it is unblocked and 
authenticated for the rest of the session. The status code 0x9000 is returned. When the PUK is wrong, 
the number of remaining retries is decreased and the SW 0x63CX, where X is the number of available retries is
returned. When the number of remaining retries reaches 0 the PUK is blocked. When the PUK is blocked this command
always returns 0x63C0, even if the PUK is inserted correctly. In this case the wallet is effectively lost.

### LOAD KEY

* CLA = 0x80
* INS = 0xD0
* P1 = 0x01 (ECC SECP256k1 keypair)
* P2 = 0x00
* Data = the key data
* Response SW = 0x9000 on success, 0x6A80 if the format is invalid, 0x6A86 if P1 is invalid
* Preconditions: Secure Channel must be opened, user PIN must be verified

At the moment P1 can only be 0x01, but new key types could be added later. The ECC SECP256k1 keypair is
encoded in [BER-TLV format](http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_annex-d.aspx) according to 
the following template

- Tag 0xA1 = keypair template
  - Tag 0x80 = ECC private key component
  - Tag 0x81 = ECC public key component

This command is used to load or replace the keypair used for signing on the card. This command always aborts open
signing sessions, if any.

### SIGN

* CLA = 0x80
* INS = 0xC0
* P1 = 0x00
* P2 = segment flag
* Data = the data to sign
* Response = if P2 indicates last segment, the signature is returned
* Response SW = 0x9000 on success, 0x6A86 if P2 is invalid
* Preconditions: Secure Channel must be opened, user PIN must be verified, a valid keypair must be loaded

P2:

* bit 0 = if 1 first block, if 0 other block
* bit 1-6 = reserved
* bit 7 = if 0 more blocks, if 1 last block

Used to sign transactions. Since the maximum short APDU size is 255 bytes the transaction must be segmented before
being sent if it is larger than that. The overhead from the Secure Channel must be also accounted for. When the last
segment is sent, the card returns the calculated signature.

The P2 parameter is used to manage the signing session and is treated as a bitmask. The rightmost bit indicates whether
this block is the first one (1) or not (0). On the first block the card resets the signature state. The leftmost bit
indicates whether this is the last block (1) or not (0). On the last block, the card generates and sends the signatures
to the client.

For example, if a signing session spans over 3 segments, the value of P2 will be respectively 0x01, 0x00, 0x80. If
the signing session is composed of a single session P2 will have the value of 0x81.

After a signature is generated, the next SIGN command must have the rightmost bit of P2 set, otherwise 0x6A86 will
be returned.

This segmentation scheme allows resuming signature sessions on power loss and at the same time avoid generating
signatures over partial data, since both the first and the last block are marked.
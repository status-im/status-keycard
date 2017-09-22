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
by the encryption). Segmentation must be handled at the application protocol.

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
* P1 = key type
* P2 = 0x00
* Data = the key data
* Response SW = 0x9000 on success, 0x6A80 if the format is invalid
* Preconditions: Secure Channel must be opened, user PIN must be verified

Used to load the keyset. TODO: specify this
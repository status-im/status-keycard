# Notes for client implementation

This document should help client application developers to integrate support for the hardware wallet in their 
applications.

## Low-level communication

The hardware wallet is a JavaCard application and as such is deployed on ISO7816 compatible SmartCards. Communication 
will happen exchanging APDUs using either the T=0 or preferably the T=1 protocol. Most operating systems use an 
implementation of [this Microsoft API](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374731(v=vs.85).aspx#smart_card_functions)
like [PCSC lite](http://pcsclite.alioth.debian.org/pcsclite.html). Your language of choice might provide bindings for
this library or an higher-level API built on top of it.

A few things to keep in mind when communicating with SmartCards

1. The card can never initiate communication. The card only responds to commands sent from the client.
2. When connecting to the card using SCardConnect, always use the SCARD_SHARE_EXCLUSIVE mode to avoid OS services
   messing with the card while you are using it.
3. A SmartCard can have multiple applications installed. If using only the basic channel (recommended for our use-case)
   only a single application can be selected at the time. This must be done explicitly on each reset by issuing the
   SELECT command with the AID of the wallet application.
4. Since we are not using extended APDUs, the maximum size of the data field of the APDU is 255 bytes.

## Wallet management and security

Before thinking about the application-specific communication (i.e: actually using the wallet applet to derive keys and
sign transactions) the client must be able to actually talk with the card using its [Secure Channel protocol](SECURE_CHANNEL.MD).

The first step, after an APDU channel is available is to [SELECT](APPLICATION.MD) the wallet application on the card.
The wallet will return its Instance UID and public key for Secure Channel establishment. Although both values are unique,
only use the Instance UID to identify the wallet since only this value is guaranteed not to change over the lifetime of
the card. If your application has already performed pairing with the wallet with this Instance UID, you can establish
a Secure Channel session (described later). Otherwise you should proceed with pairing.

For pairing, the client must show that it knows the pairing code. For this reason the user must be prompted
to insert said code. The result of pairing is a secret value shared by both parties which is used during the session key
generation on establishment of a Secure Channel. The client must permanently store the association of the Instance UID, 
the secret generated during pairing and the index which the card assigned to this client. Said index must be provided 
when opening a Secure Channel so that the card knows with which client it is speaking. Since the pairing secret is 
sensitive data, it should be stored as securely as possible, eventually with password protection. Losing this secret 
allows an attacker to pose either as the client to the card or as the card to the client.

Note that the card can only pair with a limited number of clients (currently 5). Unpairing allows to replace old clients
with new ones.

When a card and a client are paired, they can establish a Secure Channel session. The Secure Channel provides the
authentication, confidentiality and integrity guarantees which the plain APDU channel does not provide. This phase is
divided in 2 steps:

1. Sending an OPEN SECURE CHANNEL APDU to generate session keys
2. Sending a MUTUALLY AUTHENTICATE command to verify that both parties have the same keys.

After this happens, all further communication will be encrypted and with a MAC providing integrity and authentication
for each APDU.

The card and client must abort the Secure Channel session at any time if MAC verification fails, since this means that
the APDU has been corrupted, possibly as a result of an attack attempt. The card also resets the session when the
application is (re-)selected or the card is reset (or on power loss).

Note that while pairing requires user input, opening a secure channel session does not.

## User authentication

Aside from the Secure Channel-related APDUs, the application also provides commands to authenticate the user (as opposed 
as authenticating the client) and to manage the user's authentication credentials. These are the VERIFY PIN, CHANGE PIN
and UNBLOCK PIN commands. The client is not supposed to store the PIN and verification should always require user input.
After verifying the PIN the card considers to the user to be authenticated for the entire application session. The
application session ends on card reset, power loss or application re-selection. The client should keep track of whether
the user has been authenticated or not in order to avoid repeatedly asking for the PIN. The card will respond with an
error to any APDU requiring user authentication if the user has not been authenticated in the current application 
session.

## Wallet features and workflow

Now that the client can finally talk with the applet and provide user authentication facilities, it is time to look on
how to actually use the wallet. The wallet applet allows management of a single HD wallet as described in the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) 
specifications. It provides the following features

1. Source of entropy to generate master seeds (GENERATE MNEMONIC). No PIN required (has no effect on card state).
2. Loading of master key (LOAD KEY). PIN required. The same command can be used to replace the loaded master key.
3. Set the key to be used for signing by deriving from the master key (DERIVE KEY). PIN required unless a PIN-less path
   is set.
4. Sign hashes (SIGN). PIN required unless the current key path is set as PIN-less. Note that the Keccak-256 hash of the
   transaction is signed and must be generate off-card. The actual transaction data are not sent to the card.
5. Setting/Unsetting a PIN-less path (SET PINLESS PATH). PIN required. It allows disabling PIN authentication for a 
   specific key path.
6. Exporting keys (EXPORT KEY). PIN required. Currently this is only allowed if the current key path is that of the
   Whisper key (m/1/1)

Additionally the GET STATUS command (no PIN required) allows retrieving information about the card status and the
current key path.

The card is shipped with no keys on-board. In this state the SIGN and DERIVE KEY commands will not work. The client can
detect when a card has no keys by issuing a GET STATUS command. In this case it could prompt the user to either enter a
mnemonic passphrase or allow the card to generate a new one (GENERATE MNEMONIC is issued). In both cases, the mnemonic
must be converted to a master key from the client and loaded to the card using the LOAD KEY command.

The card stores the master key permanently, until replaced. Additionally the card has the concept of current key and
current key path. The current key is the one used during the SIGN command. The current key equals the master key when 
new keys are loaded and the current key path is empty. Using the DERIVE KEY command however, the client can move through 
the tree of the HD wallet. This command derives the key as described in BIP32 and sets both the current key and current 
key path according to its arguments and the results of key derivation. Using the GET STATUS command the client can
always know the current key path and thus decide if further derivation is needed or not before issuing a SIGN command.
The current key persists across application sessions (including in case of power loss). A flag in the DERIVE KEY command
decides whether derivations restarts from the master key or is performed on the current key, extending the current path.
The current maximum key path depth is 10 levels under the master key.

The SIGN command signs the Keccak-256 hash provided in the APDU's data field using the current key. The client must
calculate the hash of the transaction off-card. The signature (r,s) and the public key used to verify it are both 
returned. The client must use this to calculate 'v' and format the signature as required by Ethereum (v,r,s) if it 
wishes to submit the transaction to the network.

Another feature is the ability to define a key path which requires no PIN authentication for signing. When a PIN-less
path is set the DERIVE KEY command never requires a PIN (because there must be a PIN-less way to reach that path). Note
that setting the PIN-less key path does not automatically set the current key path to the PIN-less one. You still need
to use DERIVE KEY to get there. Only when the current key path matches the PIN-less one the SIGN command will not require
PIN authentication. The master key can never be used without PIN.

Finally, some keys can be exported (after PIN authentication). At the moment only the Whisper key (m/1/1) can be
exported. The EXPORT KEY command does not automatically do key derivation. This means that you must use DERIVE KEY first
so that the current key path matches m/1/1 and only then will the EXPORT KEY command work.

## Additional notes

1. The SIGN command also allows signing data directly instead of a precomputed hash (if P1 is 0x00 instead of 0x01), 
   transmitted over several blocks if needed. This feature is never used because this signature uses SHA-256 instead of 
   Keccak-256 (which is not available) making it useless. This mode of operation has been implemented before the current
   one with precomputed hashes. It remains because if we get hold of a hardware platform implementing Keccak-256, or we
   decide to implement it in software, we might want to operate this way.
2. The DERIVE KEY command on the current hardware platform can only be used in "assisted key derivation" mode, because
   it does not have support of the KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY algorithm. Assisted key derivation is indeed a
   workaround which should be removed if we find a suitable hardware platform (currently there is no JavaCard 3.0.5 
   implementation that can be easily found on the low-volumes market)
3. Communication has less overhead when using the T=1 protocol. However the card/reader/os combination I have seems to 
   only work with T=0 (although all claim to support T=1). Contactless readers always emulate T=1 when operated through
   the PC/SC interface.
4. You can refer to the tests for examples of communication with the card. The manual-only signTransactionTest test in
   particular generates a real transaction, signs it and submits it to the network.
5. If you test your client against our fork of jCardSim instead of a real card, keep in mind that it supports unassisted 
   key derivation, but you shouldn't use it because, as explained above, it wouldn't work on the card.
6. If using jCardSim, only use our fork, since some of the needed algorithms are unsupported in the upstream version.
7. The pairing code is a randomly generated password (using whatever password generation algorithm is desired). This
password must be converted to a 256-bit key using PBKDF2 with the salt "Status Hardware Wallet Lite" and 50000 iterations.


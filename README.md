# SafeCard

## Building and Installing

SafeCard binaries come in the form of `.cap` files, which can be created with:

```
rm -r build && ./gradlew clean && ./gradlew convertJavacard
```

This produces the following file:

```
./build/javacard/im/status/keycard/javacard/keycard.cap
```

which serves as the distribution.

The following commands are used for installation and development:

* `./gradlew install` - installs the applet
* `./gradlew build` - builds, installs, and tests the applet

## Features and Changes

This repo contains the Javacard applet that runs on the GridPlus SafeCard. It is a fork of the [Status KeyCard](https://github.com/status-im/status-keycard), with only a few notable changes. They are documented below.

### `SELECT`

The `SELECT` command returns the same data as [Status' response](https://status.im/keycard_api/apdu_select.html) with one
additional piece appended to the end of the response data:

`Tag 0x9F = SeedFlag (1 byte)`

The value will be one of the following:
* Seed not initialized: `0`
* Seed initialized but not exportable: `1`
* Seed initialized and exportable: `2`

### Certificates and Card Authentication

GridPlus SafeCards are typically used with a secure interface (the Lattice1), which queries the card for its certificates. Each cert is an ECDSA signature on the card's "authentication" public key and is signed by a GridPlus certificate authority. There are between 1 and 3 certs stored on the card.

> The GridPlus CA produces 64-byte signatures (concatenated `r` and `s` components - fixed at 32 bytes each)

#### `Load Certs (APDU 0xFA)`

This APDU allows the card issuer to load certs on a card that has not been initialized. The payload length must be a multiple of cert length (64 bytes). 

* P1: None
* P2: None
* Data: `<certs>`
* Returns: None

#### `Export Certs (APDU 0xFB)`

This APDU allows any card holder to export the loaded certs for inspection. It can be called at any point and does not require a secure channel.

* P1: None
* P2: None
* Data: None
* Returns: `[ TLV_CERTS (0x91), <len(payload)>, TLV_CERT (0x92), <len(cert0)>, <cert0>, ... TLV_CERT (0x92), <len(certN)>, <certN>]`

> `cert` is a 64-byte signature (`r` concatenated with `s`)

#### `Authenticate (APDU 0xEE)`

This APDU allows the user to request a signature on a hash from the "auth" keypair. It returns the same signature TLV template as `SIGN`.

> This APDU does not use a secure channel because authorization and verification of the card should happen before the user inputs a PIN

* P1: None
* P2: None
* Date: 32-byte hash
* return `[ TLV_SIGNATURE_TEMPLATE, 0x81, <len(payload)>, TLV_PUB_KEY, <len(pubKey)>, <pubKey>, 0x30, <len(sig)>, 0x02, <len(sig.r)>, <sig.r>, 0x02, <len(sig.s)>, <sig.s>]`

> Note that this signature template is the same as what `SIGN` would produce. I'm not sure where some of the tag byte values come from.

### Master Seed

Status does not currently save the master seed and, as such, does not allow the user to export that seed for backup purposes. This is understandable, as Status cannot assume a secure interface. However, GridPlus can - the Lattice1 (and specifically a secure compute element inside) is the main interface for SafeCards.

GridPlus has added an APDU (Export Seed) and modified two others (LoadKey/GenerateKey) to allow for storage and exporting of the card's wallet's master seed. Note that the user has full control over whether this should be exportable at all. Many users may want to restrict their seed to the card itself and never back it up. However, we felt it was important to allow an exportable option.

#### `GenerateKey (APDU 0xD4)`

Modified to allow generation and storage of master seed with exportable option.

* P1: Exportable option (0 for non-exportable, 1 for exportable)
* P2: None
* Data: None
* Returns: Key UID (not important for GridPlus)

#### `LoadKey (APDU 0xD0)`

Modified to allow storage of master seed with exportable option. 

*The following options assume you are loading a master seed:*

* P1: `0x03` (same as Status')
* P2: Exportable option (0 for non-exportable, 1 for exportable)
* Data: `<seed>`
* Returns: None

#### `Export Seed (APDU 0xC3)`

This APDU allows the card holder to export the master seed if they designated it as "exportable" when they loaded/generated it.

* P1: None
* P2: None
* Data: None
* Returns: `[ TLV_SEED (0x90), BIP39_SEED_SIZE (0x40), <seed>]`

> `seed` is a 64-byte master seed

### Intermediate Public Keys

GridPlus wishes to export intermediate public keys (e.g. `m/44'/60'/0'/`), which can be used to create fully derived (unhardened) public keys (e.g. `m/44'/60'/0'/0/0`) *outside of the card environment*. In order to do external child key derivations, we need to export the chaincode as well.

> GridPlus has modified the applet to **not allow export of private keys**. This is for various reasons, including the fact that we do allow exporting of master seeds and we allow exporting of the chaincode, which can be used with intermediate private keys to fully derive all unhardened child private keys.

#### `Export Key (APDU 0xC2)`

We have modified Export Key to allow exporting of chaincode and disallow exporting of private keys.

* P1: Same as Status
* P2: `0x02` exports public key and chaincode. `0x00` is disallowed.
* Data: Same as Status
* Returns (for P2=`0x02`): `[ TLV_PUB_KEY (0x80), PubKeyLen (0x41), <pubkey>, TLV_CHAIN_CODE (0x82), ChainCodeLen (0x20), <chaincode> ]` 


---

**[ORIGINAL STATUS DOCS BELOW]**

# What is Keycard?

Keycard is a an implementation of a BIP-32 HD wallet running on Javacard 3.0.4+ (see implementation notes)

It supports among others
- key generation, derivation and signing
- exporting keys defined in the context of EIP-1581 https://eips.ethereum.org/EIPS/eip-1581
- card duplication
- setting up a NFC NDEF tag

Communication with the Keycard happens through a simple APDU interface, together with a Secure Channel guaranteeing confidentiality, authentication and integrity of all commands. It supports both NFC and ISO7816 physical interfaces, meaning that it is compatible with any Android phone equipped with NFC, and all USB Smartcard readers.

The most obvious case for integration of Keycard is crypto wallets (ETH, BTC, etc), however it can be used in other systems where a BIP-32 key tree is used and/or you perform authentication/identification.

# Where to start?

A good place to start is our documentation site https://keycard.status.im/api/

You can also join the dicussion about this project on Status channel: https://get.status.im/chat/public/status-keycard

# How to contribute? 

Anyone is welcome to contribute to Keycard! 

Most of our communication about the project is going on here: https://get.status.im/chat/public/status-keycard

Should you wish to work on an issue, please claim it first by commenting on the GitHub issue that you want to work on it. This is to prevent duplicated efforts from contributors on the same issue.

# How to build the project?

The project is built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
You can set the JavaCard HOME not only through the environment but also creating a gradle.properties file with the 
property "com.fidesmo.gradle.javacard.home" set to the correct path.

Testing is done with JUnit and performed either on a real card or on [jCardSim](https://github.com/status-im/jcardsim). 
Although the tests are comprehensive, debugging on the real card is not easy because raw APDUs are not shown in the test 
log and there is no way to set breakpoints in the applet. 

In order to test with the simulator with an IDE, you need to pass these additional parameters to the JVM

```-noverify -Dim.status.keycard.test.target=simulator```

## Compilation
1. Download and install the JavaCard 3.0.4 SDK from [Oracle](http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-javame-419430.html#java_card_kit-classic-3_0_4-rr-bin-do)
2. Clone the Github repo for our fork of [jCardSim](https://github.com/status-im/jcardsim)
3. Create a gradle.properties (see below for an example)
4. Run `./gradlew convertJavacard`

## Installation
1. Follow all steps from the Compilation phase (except the last one)
2. Disconnect all card reader terminals from the system, except the one with the card where you want to install the applet
3. Run `./gradlew install`

## Testing
1. Follow all steps from the Installation phase (except the last one)
2. Make sure your JRE has the [JCE Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
   installed. For more information check [here](https://stackoverflow.com/questions/41580489/how-to-install-unlimited-strength-jurisdiction-policy-files).
3. Run `./gradlew test`

# What kind of smartcards can I use? 

* The applet requires JavaCard 3.0.4 (with the addition of KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY
) or later.
* The class byte of the APDU is not checked since there are no conflicting INS code.

The algorithms the card must support are at least:
* Cipher.ALG_AES_BLOCK_128_CBC_NOPAD
* Cipher.ALG_AES_CBC_ISO9797_M2
* KeyAgreement.ALG_EC_SVDP_DH_PLAIN
* KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY
* KeyPair.ALG_EC_FP (generation of 256-bit keys)
* MessageDigest.ALG_SHA_256
* MessageDigest.ALG_SHA_512
* RandomData.ALG_SECURE_RANDOM
* Signature.ALG_AES_MAC_128_NOPAD
* Signature.ALG_ECDSA_SHA_256

Best performance is achieved if the card supports:
* Signature.ALG_HMAC_SHA_512

# Other related repositories

Android installer https://github.com/status-im/keycard-installer-android/

Java SDK for Android and Desktop https://github.com/status-im/status-keycard-java

Swift SDK for iOS13 (WIP) https://github.com/status-im/Keycard.swift

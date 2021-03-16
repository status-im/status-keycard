# What is Keycard?

Keycard is an implementation of a BIP-32 HD wallet running on Javacard 3.0.4+ (see implementation notes)

It supports among others
- key generation, derivation and signing
- exporting keys defined in the context of EIP-1581 https://eips.ethereum.org/EIPS/eip-1581
- setting up a NFC NDEF tag

Communication with the Keycard happens through a simple APDU interface, together with a Secure Channel guaranteeing confidentiality, authentication and integrity of all commands. It supports both NFC and ISO7816 physical interfaces, meaning that it is compatible with any Android phone equipped with NFC, and all USB Smartcard readers.

The most obvious case for integration of Keycard is crypto wallets (ETH, BTC, etc), however it can be used in other systems where a BIP-32 key tree is used and/or you perform authentication/identification.

# Where to start?

A good place to start is our documentation site https://keycard.tech/docs/

You can also join the dicussion about this project on Status channel: https://get.status.im/chat/public/status-keycard

If you just want to use the Keycard as your hardware wallet there are currently two apps supporting it

1. WallETH [[Android](https://play.google.com/store/apps/details?id=org.walleth)]
2. Status [[Android](https://play.google.com/store/apps/details?id=im.status.ethereum)][[iOS](https://apps.apple.com/us/app/status-private-communication/id1178893006)]

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
* The GlobalPlatform ISD keys are set to c212e073ff8b4bbfaff4de8ab655221f.

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

Java SDK for Android and Desktop https://github.com/status-im/status-keycard-java

Swift SDK for iOS13 and above https://github.com/status-im/Keycard.swift

Keycard CLI for Desktop https://github.com/status-im/keycard-cli

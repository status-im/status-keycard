# JavaCard Hardware Wallet

The status.im Hardware Wallet. At the moment Secure Channel and PIN management/verification are implemented.

The project is built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
You can set the JavaCard HOME not only through the environment but also creating a gradle.properties file with the 
property "com.fidesmo.gradle.javacard.home" set to the correct path.

Loading and installing the applet requires [gpshell](https://sourceforge.net/p/globalplatform/wiki/GPShell/) to be 
installed on the system. The gradle.properties file must contain the following properties

* im.status.gradle.gpshell = the path to the gpshell executable
* im.status.gradle.gpshell.isd = the AID of the issuer security domain
* im.status.gradle.gpshell.mac_key = the MAC key for the ISD
* im.status.gradle.gpshell.enc_key = the ENC key for the ISD
* im.status.gradle.gpshell.kek_key = the KEK key for the ISD
* im.status.gradle.gpshell.kvn = the Key Version Number for the ISD
* im.status.wallet.test.simulated = true if the test should run on the simulator, false (or anything else) otherwise

Testing is done with JUnit and performed either on a real card or on [jCardSim](https://github.com/status-im/jcardsim). 
Although the tests are comprehensive, debugging on the real card is not easy because raw APDUs are not shown in the test 
log and there is no way to set breakpoints in the applet. 

In order to test with the simulator with an IDE, you need to pass these additional parameters to the JVM

```-noverify -Dim.status.wallet.test.simulated=true```

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

## Example gradle.properties file

```
com.fidesmo.gradle.javacard.home=/home/username/javacard-3_0_4
im.status.gradle.gpshell=/usr/local/bin/gpshell
im.status.gradle.gpshell.isd=A000000151000000
im.status.gradle.gpshell.mac_key=404142434445464748494a4b4c4d4e4f
im.status.gradle.gpshell.enc_key=404142434445464748494a4b4c4d4e4f
im.status.gradle.gpshell.kek_key=404142434445464748494a4b4c4d4e4f
im.status.gradle.gpshell.kvn=0
im.status.wallet.test.simulated=false
```

## Implementation notes

* The applet requires JavaCard 3.0.4 (with the addition of KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY
)or later.
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
* Signature.ALG_ECDSA_SHA_256

Best performance is achieved if the card supports:
* Signature.ALG_AES_MAC_128_NOPAD (if this is supported, then Cipher.ALG_AES_BLOCK_128_CBC_NOPAD is not required)
* Signature.ALG_HMAC_SHA_512
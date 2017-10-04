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

Testing is done with JUnit and performed on a real card. Although the tests are comprehensive, debugging is not easy 
because raw APDUs are not shown in the test log and there is no way to set breakpoints in the applet. Using a simulator
like [jCardSim](https://github.com/licel/jcardsim) would make debugging easier but only a subset of bugs can be reliably
found with this system. Code changes would be needed for tests to support jCardSim. The tests are run with the test task
in gradle.

## Example gradle.properties file

```
com.fidesmo.gradle.javacard.home=/home/username/javacard-2_2_2
im.status.gradle.gpshell=/usr/local/bin/gpshell
im.status.gradle.gpshell.isd=A000000003000000
im.status.gradle.gpshell.mac_key=404142434445464748494a4b4c4d4e4f
im.status.gradle.gpshell.enc_key=404142434445464748494a4b4c4d4e4f
im.status.gradle.gpshell.kek_key=404142434445464748494a4b4c4d4e4f
im.status.gradle.gpshell.kvn=2
```

## Implementation notes

* The class byte of the APDU is not checked since there are no conflicting INS code.
* Automated tests using JUnit 5 are included. The test require the application to be already installed. The first
  card terminal found by Java will be used, to please disconnect all card terminals except the one to be used for
  testing.
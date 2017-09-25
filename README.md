# JavaCard Hardware Wallet

Currently just a skeleton for the hardware wallet.

The .gpshell files are meant to be fed to GPShell. The statuswallet_install.gpshell file is actually dependent on the
target hw. Currently it assumes that the default VISA AID and keys for the ISD are used, but the version number is 2.

The project is built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
You can set the JavaCard HOME not only through the environment but also creating a gradle.properties file with the 
property "com.fidesmo.gradle.javacard.home" set to the correct path.

## Implementation notes

* This implementation will try to use only features available in JavaCard 2.2.2 for broader compatibility with existing
hardware.
* The class byte of the APDU is not checked since there are no conflicting INS code.
* Automated tests using JUnit 5 are included. The test require the application to be already installed. The first
  card terminal found by Java will be used, to please disconnect all card terminals except the one to be used for
  testing.
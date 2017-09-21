# JavaCard Hardware Wallet

Currently just a skeleton for the hardware wallet.

The .gpshell files are meant to be fed to GPShell. The statuswallet_install.gpshell file is actually dependent on the
target hw. Currently it assumes that the default VISA AID and keys for the ISD are used, but the version number is 2.

Other files will come and go until they are formalized as test scripts when we have a meaningful specification
and implementation.

The project is built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
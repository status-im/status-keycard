The secure channel will be needed for all APDUs in order to avoid PIN and keys being transmitted as plaintext. The basic
concept of this secure channel is to have the card generate internally an EC keyset on installation. The client should
also generate a random keyset every time it selects the applet. The public keys are exchanged and a secret is generated
using EC-DH. This secret is then used as an AES key and all communication is encrypted using this AES in CBC mode with
a random IV generated and sent for each APDU. Detailed specifications will be defined soon.
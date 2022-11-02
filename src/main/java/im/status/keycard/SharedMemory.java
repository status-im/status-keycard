package im.status.keycard;

import javacard.security.*;

/**
 * Keep references to data structures shared across applet instances of this package.
 */
class SharedMemory {
  static final short CERT_LEN = 98;

  /** The NDEF data file. Read through the NDEFApplet. **/
  static final byte[] ndefDataFile = new byte[SecureChannel.SC_MAX_PLAIN_LENGTH + 1];

  /** The Cash data file. Read through the CashApplet. **/
  static final byte[] cashDataFile = new byte[KeycardApplet.MAX_DATA_LENGTH + 1];

  /** The identification private key **/
  static ECPrivateKey idPrivate = null;

  /** The certificate. It is the concatenation of: compressed id public key, CA signature. 
   * The signature is in the format r,s,v where v allows recovering the signer public key. */  
  static final byte[] idCert = new byte[(short)(CERT_LEN + 1)];
}

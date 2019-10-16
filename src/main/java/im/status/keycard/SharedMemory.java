package im.status.keycard;

/**
 * Keep references to data structures shared across applet instances of this package.
 */
class SharedMemory {
  /** The NDEF data file. Read through the NDEFApplet. **/
  static final byte[] ndefDataFile = new byte[SecureChannel.SC_MAX_PLAIN_LENGTH + 1];

  /** The Cash data file. Read through the CashApplet. **/
  static final byte[] cashDataFile = new byte[KeycardApplet.MAX_DATA_LENGTH + 1];
}

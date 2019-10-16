package im.status.keycard;

import javacard.framework.*;

/**
 * The applet's main class. All incoming commands a processed by this class.
 */
public class NDEFApplet extends Applet {
  private static final byte INS_READ_BINARY = (byte) 0xb0;

  private static final short FILEID_NONE = (short) 0xffff;
  private static final short FILEID_NDEF_CAPS = (short) 0xe103;
  private static final short FILEID_NDEF_DATA = (short) 0xe104;

  private static final byte SELECT_P1_BY_FILEID  = (byte) 0x00;
  private static final byte SELECT_P2_FIRST_OR_ONLY = (byte) 0x0c;

  private static final short NDEF_READ_SIZE = (short) 0xff;

  private static final byte[] NDEF_CAPS_FILE = {
          (byte) 0x0f, (byte) 0x00, (byte) 0x0f, (byte) 0x20, (byte) 0x00, (byte) 0xff, (byte) 0x00, (byte) 0x01,
          (byte) 0x04, (byte) 0x06, (byte) 0xe1, (byte) 0x04, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0xff
  };

  private short selectedFile;

  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new NDEFApplet(bArray, bOffset, bLength);
  }

  /**
   * Application constructor. All memory allocation is done here. The reason for this is two-fold: first the card might
   * not have Garbage Collection so dynamic allocation will eventually eat all memory. The second reason is to be sure
   * that if the application installs successfully, there is no risk of running out of memory because of other applets
   * allocating memory. The constructor also registers the applet with the JCRE so that it becomes selectable.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public NDEFApplet(byte[] bArray, short bOffset, byte bLength) {
    short c9Off = (short)(bOffset + bArray[bOffset] + 1); // Skip AID
    c9Off += (short)(bArray[c9Off] + 1); // Skip Privileges and parameter length

    short dataLen = Util.makeShort((byte) 0x00, bArray[c9Off]);
    if ((dataLen > 2) && ((short)(dataLen - 2) == Util.makeShort(bArray[(short)(c9Off + 1)], bArray[(short)(c9Off + 2)]))) {
      Util.arrayCopyNonAtomic(bArray, c9Off, SharedMemory.ndefDataFile, (short) 0, (short)(dataLen + 1));
    }

    register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  /**
   * This method is called on every incoming APDU. This method is just a dispatcher which invokes the correct method
   * depending on the INS of the APDU.
   *
   * @param apdu the JCRE-owned APDU object.
   * @throws ISOException any processing error
   */
  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      selectedFile = FILEID_NONE;
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();

    switch (apduBuffer[ISO7816.OFFSET_INS]) {
      case ISO7816.INS_SELECT:
        processSelect(apdu);
        break;
      case INS_READ_BINARY:
        processReadBinary(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
    }
  }

  private void processSelect(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    if(apduBuffer[ISO7816.OFFSET_P1] != SELECT_P1_BY_FILEID || apduBuffer[ISO7816.OFFSET_P2] != SELECT_P2_FIRST_OR_ONLY) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    } else if (apduBuffer[ISO7816.OFFSET_LC] != 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short fid = Util.getShort(apduBuffer, ISO7816.OFFSET_CDATA);

    switch(fid) {
      case FILEID_NDEF_CAPS:
      case FILEID_NDEF_DATA:
        selectedFile = fid;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        break;
    }
  }

  private void processReadBinary(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    byte[] data;

    switch(selectedFile) {
      case FILEID_NDEF_CAPS:
        data = NDEF_CAPS_FILE;
        break;
      case FILEID_NDEF_DATA:
        data = SharedMemory.ndefDataFile;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return;
    }

    short dataLen = Util.makeShort((byte) 0x00, data[0]);
    short offset = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);

    if (offset < 0 || offset >= dataLen) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    short le = apdu.setOutgoingNoChaining();
    if (le > NDEF_READ_SIZE) {
      le = NDEF_READ_SIZE;
    }

    if((short)(offset + le) >= dataLen) {
      le = (short)(dataLen - offset);
    }

    // skip the len byte in data
    offset++;

    apdu.setOutgoingLength(le);
    apdu.sendBytesLong(data, offset, le);
  }
}

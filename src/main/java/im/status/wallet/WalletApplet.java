package im.status.wallet;

import javacard.framework.*;

public class WalletApplet extends Applet {
  static final byte INS_VERIFY_PIN = (byte) 0x20;
  static final byte INS_CHANGE_PIN = (byte) 0x21;
  static final byte INS_UNBLOCK_PIN = (byte) 0x22;
  static final byte INS_LOAD_KEY = (byte) 0xD0;
  static final byte INS_SIGN = (byte) 0xC0;

  static final byte PIN_LENGTH = 6;
  static final byte PIN_MAX_RETRIES = 3;
  static final short TMP_BUFFER_LENGTH = 32;

  private OwnerPIN ownerPIN;
  private byte[] tmp;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
  }

  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    tmp = JCSystem.makeTransientByteArray(TMP_BUFFER_LENGTH, JCSystem.CLEAR_ON_DESELECT);

    Util.arrayFillNonAtomic(tmp, (short) 0, PIN_LENGTH, (byte) 0x30);
    ownerPIN = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
    ownerPIN.update(tmp, (short) 0, PIN_LENGTH);

    register(bArray, (short) (bOffset + 1), bArray[0]);
  }

  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      apdu.setIncomingAndReceive();
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();

    switch(apduBuffer[ISO7816.OFFSET_INS]) {
      case INS_VERIFY_PIN:
        verifyPIN(apdu);
        break;
      case INS_CHANGE_PIN:
        changePIN(apdu);
        break;
      case INS_UNBLOCK_PIN:
        unblockPIN(apdu);
        break;
      case INS_LOAD_KEY:
        loadKey(apdu);
        break;
      case INS_SIGN:
        sign(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  private void verifyPIN(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    if (!ownerPIN.check(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer[ISO7816.OFFSET_LC])) {
      ISOException.throwIt((short)((short) 0x63c0 | (short) ownerPIN.getTriesRemaining()));
    }
  }

  private void changePIN(APDU apdu) {
  }

  private void unblockPIN(APDU apdu) {
  }

  private void loadKey(APDU apdu) {
  }

  private void sign(APDU apdu) {
  }
}

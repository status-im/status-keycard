package im.status.wallet;

import javacard.framework.*;
import javacard.security.ECKey;
import javacard.security.KeyPair;

public class WalletApplet extends Applet {
  static final byte INS_VERIFY_PIN = (byte) 0x20;
  static final byte INS_CHANGE_PIN = (byte) 0x21;
  static final byte INS_UNBLOCK_PIN = (byte) 0x22;
  static final byte INS_LOAD_KEY = (byte) 0xD0;
  static final byte INS_SIGN = (byte) 0xC0;

  static final byte PIN_LENGTH = 6;
  static final byte PIN_MAX_RETRIES = 3;
  static final short TMP_BUFFER_LENGTH = 32;
  public static final short EC_KEY_SIZE = 256;


  private OwnerPIN ownerPIN;
  private SecureChannel secureChannel;
  private KeyPair keypair;
  private byte[] tmp;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
  }

  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    tmp = JCSystem.makeTransientByteArray(TMP_BUFFER_LENGTH, JCSystem.CLEAR_ON_DESELECT);

    Util.arrayFillNonAtomic(tmp, (short) 0, PIN_LENGTH, (byte) 0x30);
    ownerPIN = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
    ownerPIN.update(tmp, (short) 0, PIN_LENGTH);

    secureChannel = new SecureChannel();
    keypair = new KeyPair(KeyPair.ALG_EC_FP, EC_KEY_SIZE);
    ECCurves.setSECP256K1CurveParameters((ECKey) keypair.getPrivate());
    ECCurves.setSECP256K1CurveParameters((ECKey) keypair.getPublic());

    register(bArray, (short) (bOffset + 1), bArray[0]);
  }

  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      selectApplet(apdu);
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();

    switch(apduBuffer[ISO7816.OFFSET_INS]) {
      case SecureChannel.INS_OPEN_SECURE_CHANNEL:
        secureChannel.openSecureChannel(apdu);
        break;
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
        break;
    }
  }

  private void selectApplet(APDU apdu) {
    apdu.setIncomingAndReceive();
    short keyLength = secureChannel.copyPublicKey(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, keyLength);
  }

  private void verifyPIN(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!secureChannel.isOpen()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();
    short len = secureChannel.decryptAPDU(apduBuffer);

    if (!ownerPIN.check(apduBuffer, SecureChannel.SC_OFFSET_CDATA, (byte) len)) {
      ISOException.throwIt((short)((short) 0x63c0 | (short) ownerPIN.getTriesRemaining()));
    }
  }

  private void changePIN(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && ownerPIN.isValidated())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void unblockPIN(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && ownerPIN.getTriesRemaining() == 0)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void loadKey(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && ownerPIN.isValidated())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void sign(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && ownerPIN.isValidated() && keypair.getPrivate().isInitialized())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }
}

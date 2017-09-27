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

  static final byte PUK_LENGTH = 12;
  static final byte PUK_MAX_RETRIES = 5;
  static final byte PIN_LENGTH = 6;
  static final byte PIN_MAX_RETRIES = 3;

  static final short TMP_BUFFER_LENGTH = PIN_LENGTH;
  static final short EC_KEY_SIZE = 256;


  private OwnerPIN pin;
  private OwnerPIN puk;
  private SecureChannel secureChannel;
  private KeyPair keypair;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
  }

  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    short c9Off = (short)(bOffset + bArray[bOffset] + 1);
    c9Off += (short)(bArray[bOffset] + 1 + 2);

    puk = new OwnerPIN(PUK_MAX_RETRIES, PUK_LENGTH);
    puk.update(bArray, c9Off, PUK_LENGTH);

    Util.arrayFillNonAtomic(bArray, c9Off, PIN_LENGTH, (byte) 0x30);
    pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
    pin.update(bArray, c9Off, PIN_LENGTH);

    secureChannel = new SecureChannel();
    keypair = new KeyPair(KeyPair.ALG_EC_FP, EC_KEY_SIZE);
    ECCurves.setSECP256K1CurveParameters((ECKey) keypair.getPrivate());
    ECCurves.setSECP256K1CurveParameters((ECKey) keypair.getPublic());

    register(bArray, (short) (bOffset + 1), bArray[bOffset]);
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
    byte len = secureChannel.decryptAPDU(apduBuffer);

    if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len)) {
      ISOException.throwIt((short)((short) 0x63c0 | (short) pin.getTriesRemaining()));
    }
  }

  private void changePIN(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && pin.isValidated())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();
    byte len = secureChannel.decryptAPDU(apduBuffer);

    if (!(len == 6 && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    pin.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
    pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len);
  }

  private void unblockPIN(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && pin.getTriesRemaining() == 0)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void loadKey(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && pin.isValidated())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void sign(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && pin.isValidated() && keypair.getPrivate().isInitialized())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private boolean allDigits(byte[] buffer, short off, short len) {
    while(len > 0) {
      len--;

      byte c = buffer[(short)(off+len)];

      if (c < 0x30 || c > 0x39) {
        return false;
      }
    }

    return true;
  }
}

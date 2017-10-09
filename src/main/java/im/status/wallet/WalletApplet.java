package im.status.wallet;

import javacard.framework.*;
import javacard.security.*;

public class WalletApplet extends Applet {
  static final byte INS_GET_STATUS = (byte) 0xF2;
  static final byte INS_VERIFY_PIN = (byte) 0x20;
  static final byte INS_CHANGE_PIN = (byte) 0x21;
  static final byte INS_UNBLOCK_PIN = (byte) 0x22;
  static final byte INS_LOAD_KEY = (byte) 0xD0;
  static final byte INS_DERIVE_KEY = (byte) 0xD1;
  static final byte INS_GENERATE_MNEMONIC = (byte) 0xD2;
  static final byte INS_SIGN = (byte) 0xC0;

  static final byte PUK_LENGTH = 12;
  static final byte PUK_MAX_RETRIES = 5;
  static final byte PIN_LENGTH = 6;
  static final byte PIN_MAX_RETRIES = 3;

  static final short EC_KEY_SIZE = 256;

  static final byte LOAD_KEY_P1_EC = 0x01;
  static final byte LOAD_KEY_P1_EXT_EC = 0x02;
  static final byte LOAD_KEY_P1_SEED = 0x03;

  static final byte SIGN_P1_DATA = 0x00;
  static final byte SIGN_P1_PRECOMPUTED_HASH = 0x01;

  static final byte SIGN_P2_FIRST_BLOCK_MASK = 0x01;
  static final byte SIGN_P2_LAST_BLOCK_MASK = (byte) 0x80;

  static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;

  static final byte TLV_KEY_TEMPLATE = (byte) 0xA1;
  static final byte TLV_PUB_KEY = (byte) 0x80;
  static final byte TLV_PRIV_KEY = (byte) 0x81;
  static final byte TLV_CHAIN_CODE = (byte) 0x82;

  static final byte TLV_KEY_DERIVATION_TEMPLATE = (byte) 0xA2;
  static final byte TLV_DERIVATION_SEQUENCE = (byte) 0xC0;
  static final byte TLV_DERIVED_PUB_KEY = (byte) 0xC1;
  static final byte TLV_PARENT_PUB_KEY = (byte) 0xC2;

  static final byte TLV_APPLICATION_STATUS_TEMPLATE = (byte) 0xA3;
  static final byte TLV_PIN_RETRY_COUNT = (byte) 0xC0;
  static final byte TLV_PUK_RETRY_COUNT = (byte) 0xC1;
  static final byte TLV_KEY_INITIALIZATION_STATUS = (byte) 0xC2;
  static final byte TLV_PUBLIC_KEY_DERIVATION_SUPPORTED = (byte) 0xC3;

  private OwnerPIN pin;
  private OwnerPIN puk;
  private SecureChannel secureChannel;
  private ECPublicKey publicKey;
  private ECPrivateKey privateKey;
  private Signature signature;
  private boolean signInProgress;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
  }

  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    short c9Off = (short)(bOffset + bArray[bOffset] + 1); // Skip AID
    c9Off += (short)(bArray[c9Off] + 2); // Skip Privileges and parameter length

    puk = new OwnerPIN(PUK_MAX_RETRIES, PUK_LENGTH);
    puk.update(bArray, c9Off, PUK_LENGTH);

    Util.arrayFillNonAtomic(bArray, c9Off, PIN_LENGTH, (byte) 0x30);
    pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
    pin.update(bArray, c9Off, PIN_LENGTH);

    secureChannel = new SecureChannel();
    publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EC_KEY_SIZE, false);
    privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_KEY_SIZE, false);

    ECCurves.setSECP256K1CurveParameters(publicKey);
    ECCurves.setSECP256K1CurveParameters(privateKey);

    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

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
      case INS_GET_STATUS:
        getStatus(apdu);
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
      case INS_DERIVE_KEY:
        deriveKey(apdu);
        break;
      case INS_GENERATE_MNEMONIC:
        generateMnemonic(apdu);
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
    signInProgress = false;
    pin.reset();
    puk.reset();

    apdu.setIncomingAndReceive();
    short keyLength = secureChannel.copyPublicKey(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, keyLength);
  }

  private void getStatus(APDU apdu) {
    if (!secureChannel.isOpen()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short off = SecureChannel.SC_OUT_OFFSET;
    byte[] apduBuffer = apdu.getBuffer();

    apduBuffer[off++] = TLV_APPLICATION_STATUS_TEMPLATE;
    apduBuffer[off++] = 12;
    apduBuffer[off++] = TLV_PIN_RETRY_COUNT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = pin.getTriesRemaining();
    apduBuffer[off++] = TLV_PUK_RETRY_COUNT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = puk.getTriesRemaining();
    apduBuffer[off++] = TLV_KEY_INITIALIZATION_STATUS;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = privateKey.isInitialized() ? (byte) 0x01 : (byte) 0x00;
    apduBuffer[off++] = TLV_PUBLIC_KEY_DERIVATION_SUPPORTED;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = 1; //TODO: actually check if it is supported or totally remove if a fallback software implementation is a requirement

    short len = secureChannel.encryptAPDU(apduBuffer, (short) (off - SecureChannel.SC_OUT_OFFSET));
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
  }

  private void verifyPIN(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!secureChannel.isOpen()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();
    byte len = (byte) secureChannel.decryptAPDU(apduBuffer);

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
    byte len = (byte) secureChannel.decryptAPDU(apduBuffer);

    if (!(len == PIN_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
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

    byte[] apduBuffer = apdu.getBuffer();
    byte len = (byte) secureChannel.decryptAPDU(apduBuffer);

    if (!(len == (PUK_LENGTH + PIN_LENGTH) && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (!puk.check(apduBuffer, ISO7816.OFFSET_CDATA, PUK_LENGTH)) {
      ISOException.throwIt((short)((short) 0x63c0 | (short) puk.getTriesRemaining()));
    }

    pin.resetAndUnblock();
    pin.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
    pin.check(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PUK_LENGTH), PIN_LENGTH);
    puk.reset();
  }

  private void loadKey(APDU apdu) {
    if (!(secureChannel.isOpen() && pin.isValidated())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();

    if (apduBuffer[ISO7816.OFFSET_P1] != LOAD_KEY_P1_EC)  {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    secureChannel.decryptAPDU(apduBuffer);

    short pubOffset = (short)(ISO7816.OFFSET_CDATA + 2);
    short privOffset = (short)(pubOffset + apduBuffer[(short)(pubOffset + 1)] + 2);

    if (!(apduBuffer[ISO7816.OFFSET_CDATA] == TLV_KEY_TEMPLATE && apduBuffer[pubOffset] == TLV_PUB_KEY && apduBuffer[privOffset] == TLV_PRIV_KEY))  {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();

    try {
      publicKey.setW(apduBuffer, (short) (pubOffset + 2), apduBuffer[(short) (pubOffset + 1)]);
      privateKey.setS(apduBuffer, (short) (privOffset + 2), apduBuffer[(short) (privOffset + 1)]);
    } catch (CryptoException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.commitTransaction();

    signInProgress = false;
  }

  private void deriveKey(APDU apdu) {
    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  private void generateMnemonic(APDU apdu) {
    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  private void sign(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && pin.isValidated() && privateKey.isInitialized())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();

    if ((apduBuffer[ISO7816.OFFSET_P2] & SIGN_P2_FIRST_BLOCK_MASK) == SIGN_P2_FIRST_BLOCK_MASK)  {
      signInProgress = true;
      signature.init(privateKey, Signature.MODE_SIGN);
    } else if (!signInProgress) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    short len = secureChannel.decryptAPDU(apduBuffer);

    if ((apduBuffer[ISO7816.OFFSET_P2] & SIGN_P2_LAST_BLOCK_MASK) == SIGN_P2_LAST_BLOCK_MASK) {
      signInProgress = false;

      apduBuffer[SecureChannel.SC_OUT_OFFSET] = TLV_SIGNATURE_TEMPLATE;
      apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 3)] = TLV_PUB_KEY;
      short outLen = apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 4)] = (byte) publicKey.getW(apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + 5));

      outLen += 5;

      if ((apduBuffer[ISO7816.OFFSET_P1]) == SIGN_P1_DATA) {
        outLen += signature.sign(apduBuffer, ISO7816.OFFSET_CDATA, len, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + outLen));
      } else if ((apduBuffer[ISO7816.OFFSET_P1]) == SIGN_P1_PRECOMPUTED_HASH) {
        outLen += signature.signPreComputedHash(apduBuffer, ISO7816.OFFSET_CDATA, len, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + outLen));
      } else {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }

      apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 1)] = (byte) 0x81;
      apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 2)] = (byte) (outLen - 3);

      outLen = secureChannel.encryptAPDU(apduBuffer, outLen);
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLen);
    } else {
      signature.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
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

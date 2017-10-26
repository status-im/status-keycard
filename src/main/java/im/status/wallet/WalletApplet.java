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
  static final byte INS_SET_PINLESS_PATH = (byte) 0xC1;

  static final byte PUK_LENGTH = 12;
  static final byte PUK_MAX_RETRIES = 5;
  static final byte PIN_LENGTH = 6;
  static final byte PIN_MAX_RETRIES = 3;
  static final short KEY_PATH_MAX_DEPTH = 10;

  static final short EC_KEY_SIZE = 256;
  static final short CHAIN_CODE_SIZE = 32;
  static final short SEED_SIZE = CHAIN_CODE_SIZE * 2;

  static final byte GET_STATUS_P1_APPLICATION = 0x00;
  static final byte GET_STATUS_P1_KEY_PATH = 0x01;

  static final byte LOAD_KEY_P1_EC = 0x01;
  static final byte LOAD_KEY_P1_EXT_EC = 0x02;
  static final byte LOAD_KEY_P1_SEED = 0x03;

  static final byte SIGN_P1_DATA = 0x00;
  static final byte SIGN_P1_PRECOMPUTED_HASH = 0x01;

  static final byte SIGN_P2_FIRST_BLOCK_MASK = 0x01;
  static final byte SIGN_P2_LAST_BLOCK_MASK = (byte) 0x80;

  static final byte DERIVE_P1_ASSISTED_MASK = 0x01;
  static final byte DERIVE_P1_APPEND_MASK = (byte) 0x80;

  static final byte DERIVE_P2_KEY_PATH = 0x00;
  static final byte DERIVE_P2_PUBLIC_KEY = 0x01;

  static final byte GENERATE_MNEMONIC_P1_CS_MIN = 4;
  static final byte GENERATE_MNEMONIC_P1_CS_MAX = 8;
  static final byte GENERATE_MNEMONIC_TMP_OFF = SecureChannel.SC_OUT_OFFSET + ((((GENERATE_MNEMONIC_P1_CS_MAX * 32) + GENERATE_MNEMONIC_P1_CS_MAX) / 11) * 2);

  static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;

  static final byte TLV_KEY_TEMPLATE = (byte) 0xA1;
  static final byte TLV_PUB_KEY = (byte) 0x80;
  static final byte TLV_PRIV_KEY = (byte) 0x81;
  static final byte TLV_CHAIN_CODE = (byte) 0x82;

  static final byte TLV_KEY_DERIVATION_TEMPLATE = (byte) 0xA2;
  static final byte TLV_PUB_X = (byte) 0x83;

  static final byte TLV_APPLICATION_STATUS_TEMPLATE = (byte) 0xA3;
  static final byte TLV_PIN_RETRY_COUNT = (byte) 0xC0;
  static final byte TLV_PUK_RETRY_COUNT = (byte) 0xC1;
  static final byte TLV_KEY_INITIALIZATION_STATUS = (byte) 0xC2;
  static final byte TLV_PUBLIC_KEY_DERIVATION = (byte) 0xC3;

  private static final byte[] ASSISTED_DERIVATION_HASH = { (byte) 0xAA, (byte) 0x2D, (byte) 0xA9, (byte) 0x9D, (byte) 0x91, (byte) 0x8C, (byte) 0x7D, (byte) 0x95, (byte) 0xB8, (byte) 0x96, (byte) 0x89, (byte) 0x87, (byte) 0x3E, (byte) 0xAA, (byte) 0x37, (byte) 0x67, (byte) 0x25, (byte) 0x0C, (byte) 0xFF, (byte) 0x50, (byte) 0x13, (byte) 0x9A, (byte) 0x2F, (byte) 0x87, (byte) 0xBB, (byte) 0x4F, (byte) 0xCA, (byte) 0xB4, (byte) 0xAE, (byte) 0xC3, (byte) 0xE8, (byte) 0x90};

  private OwnerPIN pin;
  private OwnerPIN puk;
  private SecureChannel secureChannel;

  private ECPublicKey masterPublic;
  private ECPrivateKey masterPrivate;
  private byte[] masterChainCode;
  private boolean isExtended;

  private ECPublicKey publicKey;
  private ECPrivateKey privateKey;
  private byte[] chainCode;

  private byte[] keyPath;
  private short keyPathLen;

  private byte[] pinlessPath;
  private short pinlessPathLen;

  private Signature signature;
  private boolean signInProgress;
  private boolean expectPublicKey;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
  }

  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    SECP256k1.init();
    Crypto.init();

    short c9Off = (short)(bOffset + bArray[bOffset] + 1); // Skip AID
    c9Off += (short)(bArray[c9Off] + 2); // Skip Privileges and parameter length

    puk = new OwnerPIN(PUK_MAX_RETRIES, PUK_LENGTH);
    puk.update(bArray, c9Off, PUK_LENGTH);

    Util.arrayFillNonAtomic(bArray, c9Off, PIN_LENGTH, (byte) 0x30);
    pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
    pin.update(bArray, c9Off, PIN_LENGTH);

    secureChannel = new SecureChannel();

    masterPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EC_KEY_SIZE, false);
    masterPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_KEY_SIZE, false);
    masterChainCode = new byte[32];
    chainCode = new byte[32];
    keyPath = new byte[KEY_PATH_MAX_DEPTH * 4];
    pinlessPath = new byte[KEY_PATH_MAX_DEPTH * 4];

    publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EC_KEY_SIZE, false);
    privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_KEY_SIZE, false);

    SECP256k1.setCurveParameters(masterPublic);
    SECP256k1.setCurveParameters(masterPrivate);

    SECP256k1.setCurveParameters(publicKey);
    SECP256k1.setCurveParameters(privateKey);

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
      case INS_SET_PINLESS_PATH:
        setPinlessPath(apdu);
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

    short len;

    if (apduBuffer[ISO7816.OFFSET_P1] == GET_STATUS_P1_APPLICATION) {
      len = getApplicationStatus(apduBuffer, off);
    } else if (apduBuffer[ISO7816.OFFSET_P1] == GET_STATUS_P1_KEY_PATH) {
      len = getKeyStatus(apduBuffer, off);
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return;
    }

    len = secureChannel.encryptAPDU(apduBuffer, len);
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
  }

  private short getApplicationStatus(byte[] apduBuffer, short off) {
    apduBuffer[off++] = TLV_APPLICATION_STATUS_TEMPLATE;
    apduBuffer[off++] = 9;
    apduBuffer[off++] = TLV_PIN_RETRY_COUNT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = pin.getTriesRemaining();
    apduBuffer[off++] = TLV_PUK_RETRY_COUNT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = puk.getTriesRemaining();
    apduBuffer[off++] = TLV_KEY_INITIALIZATION_STATUS;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = privateKey.isInitialized() ? (byte) 0x01 : (byte) 0x00;
    apduBuffer[off++] = TLV_PUBLIC_KEY_DERIVATION;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = SECP256k1.hasECPointMultiplication() ? (byte) 0x01 : (byte) 0x00;

    return (short) (off - SecureChannel.SC_OUT_OFFSET);
  }

  private short getKeyStatus(byte[] apduBuffer, short off) {
    if (expectPublicKey) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    Util.arrayCopyNonAtomic(keyPath, (short) 0, apduBuffer, off, keyPathLen);
    return keyPathLen;
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
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && pin.isValidated())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();

    secureChannel.decryptAPDU(apduBuffer);
    boolean newExtended = false;

    switch (apduBuffer[ISO7816.OFFSET_P1])  {
      case LOAD_KEY_P1_EXT_EC:
        newExtended = true;
      case LOAD_KEY_P1_EC:
        loadKeyPair(apduBuffer, newExtended);
        break;
      case LOAD_KEY_P1_SEED:
        loadSeed(apduBuffer);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        break;
    }

    signInProgress = false;
    expectPublicKey = false;
    keyPathLen = 0;
  }

  private void loadKeyPair(byte[] apduBuffer, boolean newExtended) {
    short pubOffset = (short)(ISO7816.OFFSET_CDATA + (apduBuffer[(short) (ISO7816.OFFSET_CDATA + 1)] == (byte) 0x81 ? 3 : 2));
    short privOffset = (short)(pubOffset + apduBuffer[(short)(pubOffset + 1)] + 2);
    short chainOffset = (short)(privOffset + apduBuffer[(short)(privOffset + 1)] + 2);

    if (apduBuffer[pubOffset] != TLV_PUB_KEY) {
      SECP256k1.assetECPointMultiplicationSupport();
      chainOffset = privOffset;
      privOffset = pubOffset;
      pubOffset = -1;
    }

    if (!((apduBuffer[ISO7816.OFFSET_CDATA] == TLV_KEY_TEMPLATE) && (apduBuffer[privOffset] == TLV_PRIV_KEY) && (!newExtended || apduBuffer[chainOffset] == TLV_CHAIN_CODE)))  {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();

    try {
      isExtended = newExtended;

      masterPrivate.setS(apduBuffer, (short) (privOffset + 2), apduBuffer[(short) (privOffset + 1)]);
      privateKey.setS(apduBuffer, (short) (privOffset + 2), apduBuffer[(short) (privOffset + 1)]);

      if (isExtended) {
        if (apduBuffer[(short) (chainOffset + 1)] == CHAIN_CODE_SIZE) {
          Util.arrayCopy(apduBuffer, (short) (chainOffset + 2), masterChainCode, (short) 0, apduBuffer[(short) (chainOffset + 1)]);
          Util.arrayCopy(apduBuffer, (short) (chainOffset + 2), chainCode, (short) 0, apduBuffer[(short) (chainOffset + 1)]);
        } else {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
      }

      short pubLen;

      if (pubOffset != -1) {
        pubLen = apduBuffer[(short) (pubOffset + 1)];
        pubOffset = (short) (pubOffset + 2);
      } else {
        pubOffset = 0;
        pubLen = SECP256k1.derivePublicKey(masterPrivate, apduBuffer, pubOffset);
      }

      masterPublic.setW(apduBuffer, pubOffset, pubLen);
      publicKey.setW(apduBuffer, pubOffset, pubLen);
    } catch (CryptoException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.commitTransaction();
  }

  private void loadSeed(byte[] apduBuffer) {
    SECP256k1.assetECPointMultiplicationSupport();

    if (apduBuffer[ISO7816.OFFSET_LC] != SEED_SIZE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();
    isExtended = true;

    masterPrivate.setS(apduBuffer, (short) ISO7816.OFFSET_CDATA, CHAIN_CODE_SIZE);
    privateKey.setS(apduBuffer, (short) ISO7816.OFFSET_CDATA, CHAIN_CODE_SIZE);

    Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + CHAIN_CODE_SIZE), masterChainCode, (short) 0, CHAIN_CODE_SIZE);
    Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + CHAIN_CODE_SIZE), chainCode, (short) 0, CHAIN_CODE_SIZE);
    short pubLen = SECP256k1.derivePublicKey(masterPrivate, apduBuffer, (short) 0);

    masterPublic.setW(apduBuffer, (short) 0, pubLen);
    publicKey.setW(apduBuffer, (short) 0, pubLen);

    JCSystem.commitTransaction();
  }

  private void deriveKey(APDU apdu) {
    if (!(secureChannel.isOpen() && (pin.isValidated() || (pinlessPathLen > 0)) && isExtended)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();

    apdu.setIncomingAndReceive();
    short len = secureChannel.decryptAPDU(apduBuffer);

    boolean assistedDerivation = (apduBuffer[ISO7816.OFFSET_P1] & DERIVE_P1_ASSISTED_MASK) == DERIVE_P1_ASSISTED_MASK;
    boolean isPublicKey = apduBuffer[ISO7816.OFFSET_P2]  == DERIVE_P2_PUBLIC_KEY;
    boolean isReset = (apduBuffer[ISO7816.OFFSET_P1] & DERIVE_P1_APPEND_MASK) != DERIVE_P1_APPEND_MASK;

    if ((isPublicKey != (expectPublicKey && !isReset)) || (isPublicKey && !assistedDerivation)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    if (isPublicKey) {
      publicKey.setW(apduBuffer, ISO7816.OFFSET_CDATA, len);
      expectPublicKey = false;
      keyPathLen += 4;
      return;
    }

    if (((short) (len % 4) != 0) || (assistedDerivation && (len > 4)) || ((short)(len + (isReset ? 0 : keyPathLen)) > keyPath.length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if ((len != 0) && !assistedDerivation) {
      SECP256k1.assetECPointMultiplicationSupport();
    }

    short chainEnd = (short) (ISO7816.OFFSET_CDATA + len);

    if (isReset) {
      resetKeys(apduBuffer, chainEnd);
      expectPublicKey = false;
      keyPathLen = 0;
    }

    signInProgress = false;

    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, keyPath, keyPathLen, len);

    for (short i = ISO7816.OFFSET_CDATA; i < chainEnd; i += 4) {
      Crypto.bip32CKDPriv(apduBuffer, i, privateKey, publicKey, chainCode, (short) 0);

      if (assistedDerivation) {
        expectPublicKey = true;
        outputPublicX(apdu, apduBuffer);
        return;
      } else {
        short pubLen = SECP256k1.derivePublicKey(privateKey, apduBuffer, chainEnd);
        publicKey.setW(apduBuffer, chainEnd, pubLen);
      }
    }

    expectPublicKey = false;
    keyPathLen += len;
  }

  private void outputPublicX(APDU apdu, byte[] apduBuffer) {
    short xLen = SECP256k1.derivePublicX(privateKey, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + 4));

    signature.init(privateKey, Signature.MODE_SIGN);
    short sigLen = signature.signPreComputedHash(ASSISTED_DERIVATION_HASH, (short) 0, (short) ASSISTED_DERIVATION_HASH.length, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + xLen + 4));

    apduBuffer[SecureChannel.SC_OUT_OFFSET] = TLV_KEY_DERIVATION_TEMPLATE;
    apduBuffer[(short) (SecureChannel.SC_OUT_OFFSET + 1)] = (byte) (xLen + sigLen + 2);
    apduBuffer[(short) (SecureChannel.SC_OUT_OFFSET + 2)] = TLV_PUB_X;
    apduBuffer[(short) (SecureChannel.SC_OUT_OFFSET + 3)] = (byte) xLen;

    short outLen = secureChannel.encryptAPDU(apduBuffer, (short) (xLen + sigLen + 4));
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLen);
  }

  private void resetKeys(byte[] buffer, short offset) {
    short pubOff = (short) (offset + masterPrivate.getS(buffer, offset));
    short pubLen = masterPublic.getW(buffer, pubOff);

    JCSystem.beginTransaction();
    Util.arrayCopy(masterChainCode, (short) 0, chainCode, (short) 0, CHAIN_CODE_SIZE);
    privateKey.setS(buffer, offset, CHAIN_CODE_SIZE);
    publicKey.setW(buffer, pubOff, pubLen);
    JCSystem.commitTransaction();
  }

  private void generateMnemonic(APDU apdu) {
    if (!secureChannel.isOpen()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();
    short csLen = apduBuffer[ISO7816.OFFSET_P1];

    if (csLen < GENERATE_MNEMONIC_P1_CS_MIN || csLen > GENERATE_MNEMONIC_P1_CS_MAX)  {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    short entLen = (short) (csLen * 4);
    Crypto.random.generateData(apduBuffer, GENERATE_MNEMONIC_TMP_OFF, entLen);
    Crypto.sha256.doFinal(apduBuffer, GENERATE_MNEMONIC_TMP_OFF, entLen, apduBuffer, (short)(GENERATE_MNEMONIC_TMP_OFF + entLen));
    entLen += GENERATE_MNEMONIC_TMP_OFF + 1;

    short outOff = SecureChannel.SC_OUT_OFFSET;
    short rShift = 0;
    short vp = 0;

    for (short i = GENERATE_MNEMONIC_TMP_OFF; i < entLen; i += 2) {
      short w = Util.getShort(apduBuffer, i);
      Util.setShort(apduBuffer, outOff, logicrShift((short) (vp | logicrShift(w, rShift)), (short) 5));
      outOff += 2;
      rShift += 5;
      vp = (short) (w << (16 - rShift));

      if (rShift >= 11) {
        Util.setShort(apduBuffer, outOff, logicrShift(vp, (short) 5));
        outOff += 2;
        rShift = (short) (rShift - 11);
        vp = (short) (w << (16 - rShift));
      }
    }

    if (csLen < 6) {
      outOff -= 2; // a last spurious 11 bit number will be generated when cs length is less than 6 because 16 - cs >= 11
    }

    short outLen = secureChannel.encryptAPDU(apduBuffer, (short) (outOff - SecureChannel.SC_OUT_OFFSET));
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLen);
  }

  // This works on simulator AND on JavaCard. Since we do not do a lot of these operations, the performance hit is non-existent
  private short logicrShift(short v, short amount) {
    if (amount == 0) return v; // short circuit on 0
    short tmp = (short) (v & 0x7fff);

    if (tmp == v) {
      return (short) (v >>> amount);
    }

    tmp = (short) (tmp >>> amount);

    return (short) ((short)((short) 0x4000 >>> (short) (amount - 1)) | tmp);
  }

  private void sign(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && (pin.isValidated() || isPinless()) && privateKey.isInitialized() && !expectPublicKey)) {
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

  private void setPinlessPath(APDU apdu) {
    apdu.setIncomingAndReceive();

    if (!(secureChannel.isOpen() && pin.isValidated())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();
    short len = secureChannel.decryptAPDU(apduBuffer);

    if (((short) (len % 4) != 0) || (len > pinlessPath.length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();
    pinlessPathLen = len;
    Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, pinlessPath, (short) 0, len);
    JCSystem.commitTransaction();
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

  private boolean isPinless() {
    return (pinlessPathLen > 0) && (pinlessPathLen == keyPathLen) && (Util.arrayCompare(keyPath, (short) 0, pinlessPath, (short) 0, keyPathLen) == 0);
  }
}

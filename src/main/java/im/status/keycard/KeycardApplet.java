package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * The applet's main class. All incoming commands a processed by this class.
 */
public class KeycardApplet extends Applet {
  static final short APPLICATION_VERSION = (short) 0x0202;

  static final byte INS_GET_STATUS = (byte) 0xF2;
  static final byte INS_SET_NDEF = (byte) 0xF3;
  static final byte INS_INIT = (byte) 0xFE;
  static final byte INS_VERIFY_PIN = (byte) 0x20;
  static final byte INS_CHANGE_PIN = (byte) 0x21;
  static final byte INS_UNBLOCK_PIN = (byte) 0x22;
  static final byte INS_LOAD_KEY = (byte) 0xD0;
  static final byte INS_DERIVE_KEY = (byte) 0xD1;
  static final byte INS_GENERATE_MNEMONIC = (byte) 0xD2;
  static final byte INS_REMOVE_KEY = (byte) 0xD3;
  static final byte INS_GENERATE_KEY = (byte) 0xD4;
  static final byte INS_DUPLICATE_KEY = (byte) 0xD5;
  static final byte INS_SIGN = (byte) 0xC0;
  static final byte INS_SET_PINLESS_PATH = (byte) 0xC1;
  static final byte INS_EXPORT_KEY = (byte) 0xC2;
  static final byte INS_EXPORT_SEED = (byte) 0xC3;

  static final short SW_REFERENCED_DATA_NOT_FOUND = (short) 0x6A88;

  static final byte PUK_LENGTH = 12;
  static final byte PUK_MAX_RETRIES = 5;
  static final byte PIN_LENGTH = 6;
  static final byte PIN_MAX_RETRIES = 3;
  static final byte KEY_PATH_MAX_DEPTH = 10;
  static final byte PAIRING_MAX_CLIENT_COUNT = 1;
  static final byte UID_LENGTH = 16;

  static final short CHAIN_CODE_SIZE = 32;
  static final short KEY_UID_LENGTH = 32;
  static final short BIP39_SEED_SIZE = CHAIN_CODE_SIZE * 2;

  static final byte GET_STATUS_P1_APPLICATION = 0x00;
  static final byte GET_STATUS_P1_KEY_PATH = 0x01;

  static final byte CHANGE_PIN_P1_USER_PIN = 0x00;
  static final byte CHANGE_PIN_P1_PUK = 0x01;
  static final byte CHANGE_PIN_P1_PAIRING_SECRET = 0x02;

  static final byte LOAD_KEY_P1_EC = 0x01;
  static final byte LOAD_KEY_P1_EXT_EC = 0x02;
  static final byte LOAD_KEY_P1_SEED = 0x03;

  static final byte DERIVE_P1_SOURCE_MASTER = (byte) 0x00;
  static final byte DERIVE_P1_SOURCE_PARENT = (byte) 0x40;
  static final byte DERIVE_P1_SOURCE_CURRENT = (byte) 0x80;
  static final byte DERIVE_P1_SOURCE_MASK = (byte) 0xC0;

  static final byte GENERATE_MNEMONIC_P1_CS_MIN = 4;
  static final byte GENERATE_MNEMONIC_P1_CS_MAX = 8;
  static final byte GENERATE_MNEMONIC_TMP_OFF = SecureChannel.SC_OUT_OFFSET + ((((GENERATE_MNEMONIC_P1_CS_MAX * 32) + GENERATE_MNEMONIC_P1_CS_MAX) / 11) * 2);

  static final byte DUPLICATE_KEY_P1_START = 0x00;
  static final byte DUPLICATE_KEY_P1_ADD_ENTROPY = 0x01;
  static final byte DUPLICATE_KEY_P1_EXPORT = 0x02;
  static final byte DUPLICATE_KEY_P1_IMPORT = 0x03;

  static final byte SIGN_P1_CURRENT_KEY = 0x00;
  static final byte SIGN_P1_DERIVE = 0x01;
  static final byte SIGN_P1_DERIVE_AND_MAKE_CURRENT = 0x02;
  static final byte SIGN_P1_PINLESS = 0x03;

  static final byte EXPORT_KEY_P1_CURRENT = 0x00;
  static final byte EXPORT_KEY_P1_DERIVE = 0x01;
  static final byte EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT = 0x02;

  // static final byte EXPORT_KEY_P2_PRIVATE_AND_PUBLIC = 0x00; // Unsupported
  static final byte EXPORT_KEY_P2_PUBLIC_ONLY = 0x01;
  static final byte EXPORT_KEY_P2_PUBLIC_AND_CHAINCODE = 0x02;

  static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;

  static final byte TLV_KEY_TEMPLATE = (byte) 0xA1;
  static final byte TLV_PUB_KEY = (byte) 0x80;
  static final byte TLV_PRIV_KEY = (byte) 0x81;
  static final byte TLV_CHAIN_CODE = (byte) 0x82;
  static final byte TLV_SEED = (byte) 0x83;
  static final byte TLV_SEED_STATUS = (byte) 0x84;

  static final byte TLV_APPLICATION_STATUS_TEMPLATE = (byte) 0xA3;
  static final byte TLV_INT = (byte) 0x02;
  static final byte TLV_BOOL = (byte) 0x01;

  static final byte TLV_APPLICATION_INFO_TEMPLATE = (byte) 0xA4;
  static final byte TLV_UID = (byte) 0x8F;
  static final byte TLV_KEY_UID = (byte) 0x8E;
  static final byte TLV_CAPABILITIES = (byte) 0x8D;

  static final byte CAPABILITY_SECURE_CHANNEL = (byte) 0x01;
  static final byte CAPABILITY_KEY_MANAGEMENT = (byte) 0x02;
  static final byte CAPABILITY_CREDENTIALS_MANAGEMENT = (byte) 0x04;
  static final byte CAPABILITY_NDEF = (byte) 0x08;

  static final byte APPLICATION_CAPABILITIES = (byte)(CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT | CAPABILITY_NDEF);

  static final byte[] EIP_1581_PREFIX = { (byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D};
  
  static final byte MASTERSEED_EMPTY = 0;
  static final byte MASTERSEED_NOT_EXPORTABLE = 1;
  static final byte MASTERSEED_EXPORTABLE = 2;

  private OwnerPIN pin;
  private OwnerPIN puk;
  private byte[] uid;
  private SecureChannel secureChannel;

  private byte[] masterSeed;
  private byte masterSeedStatus; // Invalid / valid, but non-exportable / valid and exportable
  private ECPublicKey masterPublic;
  private ECPrivateKey masterPrivate;
  private byte[] masterChainCode;
  private boolean isExtended;

  private ECPublicKey parentPublicKey;
  private ECPrivateKey parentPrivateKey;
  private byte[] parentChainCode;

  private ECPublicKey publicKey;
  private ECPrivateKey privateKey;
  private byte[] chainCode;

  private ECPublicKey pinlessPublicKey;
  private ECPrivateKey pinlessPrivateKey;

  private byte[] keyPath;
  private short keyPathLen;

  private byte[] pinlessPath;
  private short pinlessPathLen;

  private Signature signature;

  private byte[] keyUID;

  private Crypto crypto;
  private SECP256k1 secp256k1;

  private byte[] duplicationEncKey;
  private short expectedEntropy;

  private byte[] derivationOutput;

  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new KeycardApplet(bArray, bOffset, bLength);
  }

  /**
   * Application constructor. All memory allocation is done here and in the init function. The reason for this is
   * two-fold: first the card might not have Garbage Collection so dynamic allocation will eventually eat all memory.
   * The second reason is to be sure that if the application installs successfully, there is no risk of running out
   * of memory because of other applets allocating memory. The constructor also registers the applet with the JCRE so
   * that it becomes selectable.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public KeycardApplet(byte[] bArray, short bOffset, byte bLength) {
    crypto = new Crypto();
    secp256k1 = new SECP256k1(crypto);
    secureChannel = new SecureChannel(PAIRING_MAX_CLIENT_COUNT, crypto, secp256k1);

    uid = new byte[UID_LENGTH];
    crypto.random.generateData(uid, (short) 0, UID_LENGTH);
    
    masterSeed = new byte[BIP39_SEED_SIZE];
    masterSeedStatus = MASTERSEED_EMPTY;

    masterPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    masterPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);

    parentPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    parentPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);

    publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);

    pinlessPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    pinlessPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);

    masterChainCode = new byte[CHAIN_CODE_SIZE];
    parentChainCode = new byte[CHAIN_CODE_SIZE];
    chainCode = new byte[CHAIN_CODE_SIZE];
    keyPath = new byte[KEY_PATH_MAX_DEPTH * 4];
    pinlessPath = new byte[KEY_PATH_MAX_DEPTH * 4];

    keyUID = new byte[KEY_UID_LENGTH];

    resetCurveParameters();

    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    duplicationEncKey = new byte[(short)(KeyBuilder.LENGTH_AES_256/8)];
    expectedEntropy = -1;

    derivationOutput = JCSystem.makeTransientByteArray((short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE), JCSystem.CLEAR_ON_RESET);

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
    // If we have no PIN it means we still have to initialize the applet.
    if (pin == null) {
      processInit(apdu);
      return;
    }

    // Since selection can happen not only by a SELECT command, we check for that separately.
    if (selectingApplet()) {
      selectApplet(apdu);
      return;
    }

    apdu.setIncomingAndReceive();
    byte[] apduBuffer = apdu.getBuffer();

    try {
      switch (apduBuffer[ISO7816.OFFSET_INS]) {
        case SecureChannel.INS_OPEN_SECURE_CHANNEL:
          secureChannel.openSecureChannel(apdu);
          break;
        case SecureChannel.INS_MUTUALLY_AUTHENTICATE:
          secureChannel.mutuallyAuthenticate(apdu);
          break;
        case SecureChannel.INS_PAIR:
          secureChannel.pair(apdu);
          break;
        case SecureChannel.INS_UNPAIR:
          unpair(apdu);
          break;
        case INS_GET_STATUS:
          getStatus(apdu);
          break;
        case INS_SET_NDEF:
          setNDEF(apdu);
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
        case INS_REMOVE_KEY:
          removeKey(apdu);
          break;
        case INS_GENERATE_KEY:
          generateKey(apdu);
          break;
        case INS_DUPLICATE_KEY:
          duplicateKey(apdu);
          break;
        case INS_SIGN:
          sign(apdu);
          break;
        case INS_SET_PINLESS_PATH:
          setPinlessPath(apdu);
          break;
        case INS_EXPORT_KEY:
          exportKey(apdu);
          break;
        case INS_EXPORT_SEED:
          exportSeed(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          break;
      }
    } catch(ISOException sw) {
      handleException(apdu, sw.getReason());
    } catch (CryptoException ce) {
      handleException(apdu, (short)(ISO7816.SW_UNKNOWN | ce.getReason()));
    } catch (Exception e) {
      handleException(apdu, ISO7816.SW_UNKNOWN);
    }

    if (shouldRespond(apdu)) {
      secureChannel.respond(apdu, (short) 0, ISO7816.SW_NO_ERROR);
    }
  }

  private void handleException(APDU apdu, short sw) {
    if (shouldRespond(apdu) && (sw != ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED)) {
      secureChannel.respond(apdu, (short) 0, sw);
    } else {
      ISOException.throwIt(sw);
    }
  }

  /**
   * Processes the init command, this is invoked only if the applet has not yet been personalized with secrets.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void processInit(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    if (selectingApplet()) {
      apduBuffer[0] = TLV_PUB_KEY;
      apduBuffer[1] = (byte) secureChannel.copyPublicKey(apduBuffer, (short) 2);
      apdu.setOutgoingAndSend((short) 0, (short)(apduBuffer[1] + 2));
    } else if (apduBuffer[ISO7816.OFFSET_INS] == INS_INIT) {
      secureChannel.oneShotDecrypt(apduBuffer);

      if ((apduBuffer[ISO7816.OFFSET_LC] != (byte)(PIN_LENGTH + PUK_LENGTH + SecureChannel.SC_SECRET_LENGTH)) || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, (short)(PIN_LENGTH + PUK_LENGTH))) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      JCSystem.beginTransaction();
      secureChannel.initSecureChannel(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH + PUK_LENGTH));

      pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
      pin.update(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);

      puk = new OwnerPIN(PUK_MAX_RETRIES, PUK_LENGTH);
      puk.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH), PUK_LENGTH);

      JCSystem.commitTransaction();
    } else {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  private boolean shouldRespond(APDU apdu) {
    return secureChannel.isOpen() && (apdu.getCurrentState() != APDU.STATE_FULL_OUTGOING);
  }

  /**
   * Checks that the PIN is validated and if it is call the unpair method of the secure channel. If the PIN is not
   * validated the 0x6985 exception is thrown.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void unpair(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (pin.isValidated()) {
      secureChannel.unpair(apduBuffer);
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  /**
   * Invoked on applet (re-)selection. Aborts any in-progress signing session and sets PIN and PUK to not verified.
   * Responds with a SECP256k1 public key which the client must use to establish a secure channel.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void selectApplet(APDU apdu) {
    pin.reset();
    puk.reset();
    secureChannel.reset();
    secureChannel.updateSecureChannelCounter();

    byte[] apduBuffer = apdu.getBuffer();

    short off = 0;

    apduBuffer[off++] = TLV_APPLICATION_INFO_TEMPLATE;

    if (privateKey.isInitialized()) {
      apduBuffer[off++] = (byte) 0x81;
    }

    short lenoff = off++;

    apduBuffer[off++] = TLV_UID;
    apduBuffer[off++] = UID_LENGTH;
    Util.arrayCopyNonAtomic(uid, (short) 0, apduBuffer, off, UID_LENGTH);
    off += UID_LENGTH;

    apduBuffer[off++] = TLV_PUB_KEY;
    short keyLength = secureChannel.copyPublicKey(apduBuffer, (short) (off + 1));
    apduBuffer[off++] = (byte) keyLength;
    off += keyLength;

    apduBuffer[off++] = TLV_INT;
    apduBuffer[off++] = 2;
    Util.setShort(apduBuffer, off, APPLICATION_VERSION);
    off += 2;

    apduBuffer[off++] = TLV_INT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = secureChannel.getRemainingPairingSlots();
    apduBuffer[off++] = TLV_KEY_UID;

    if (privateKey.isInitialized()) {
      apduBuffer[off++] = KEY_UID_LENGTH;
      Util.arrayCopyNonAtomic(keyUID, (short) 0, apduBuffer, off, KEY_UID_LENGTH);
      off += KEY_UID_LENGTH;
    } else {
      apduBuffer[off++] = 0;
    }

    apduBuffer[off++] = TLV_CAPABILITIES;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = APPLICATION_CAPABILITIES;

    apduBuffer[off++] = TLV_SEED_STATUS;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = masterSeedStatus;

    apduBuffer[lenoff] = (byte)(off - lenoff - 1);
    apdu.setOutgoingAndSend((short) 0, off);
  }

  /**
   * Processes the GET STATUS command according to the application's specifications. This command is always a Case-2 APDU.
   * Requires an open secure channel but does not check if the PIN has been verified.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void getStatus(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    short len;

    if (apduBuffer[ISO7816.OFFSET_P1] == GET_STATUS_P1_APPLICATION) {
      len = getApplicationStatus(apduBuffer, SecureChannel.SC_OUT_OFFSET);
    } else if (apduBuffer[ISO7816.OFFSET_P1] == GET_STATUS_P1_KEY_PATH) {
      len = getKeyStatus(apduBuffer, SecureChannel.SC_OUT_OFFSET);
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return;
    }

    secureChannel.respond(apdu, len, ISO7816.SW_NO_ERROR);
  }

  /**
   * Sets the content of the NDEF data file returned by the NDEF applet. Requires a secure channel to be already open
   * and the PIN to be verified.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void setNDEF(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short dataLen = Util.makeShort((byte) 0x00, apduBuffer[ISO7816.OFFSET_LC]);
    short offset;

    if (Util.makeShort(apduBuffer[ISO7816.OFFSET_CDATA], apduBuffer[(short)(ISO7816.OFFSET_CDATA + 1)]) != (short)(dataLen - 2)) {
      offset = ISO7816.OFFSET_P2;
      apduBuffer[ISO7816.OFFSET_P2] = 0;
      dataLen += 2;
    } else {
      offset = ISO7816.OFFSET_CDATA;
    }

    JCSystem.beginTransaction();
    Util.arrayCopy(apduBuffer, offset, SharedMemory.ndefDataFile, (short) 0, dataLen);
    JCSystem.commitTransaction();
  }

  /**
   * Writes the Application Status Template to the APDU buffer. Invoked internally by the getStatus method. This
   * template is useful to understand if the card is blocked, if it has valid keys and if public key derivation is
   * supported.
   *
   * @param apduBuffer the APDU buffer
   * @param off the offset in the buffer where the application status template must be written at.
   * @return the length in bytes of the data to output
   */
  private short getApplicationStatus(byte[] apduBuffer, short off) {
    apduBuffer[off++] = TLV_APPLICATION_STATUS_TEMPLATE;
    apduBuffer[off++] = 9;
    apduBuffer[off++] = TLV_INT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = pin.getTriesRemaining();
    apduBuffer[off++] = TLV_INT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = puk.getTriesRemaining();
    apduBuffer[off++] = TLV_BOOL;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = privateKey.isInitialized() ? (byte) 0xFF : (byte) 0x00;

    return (short) (off - SecureChannel.SC_OUT_OFFSET);
  }

  /**
   * Writes the key path status to the APDU buffer. Invoked internally by the getStatus method. The key path indicates
   * at which point in the BIP32 hierarchy we are at. The data is unformatted and is simply a sequence of 32-bit
   * big endian integers. The Master key is not indicated so nothing will be written if no derivation has been performed.
   * However, because of the secure channel, the response will still contain the IV and the padding.
   *
   * @param apduBuffer the APDU buffer
   * @param off the offset in the buffer where the key status template must be written at.
   * @return the length in bytes of the data to output
   */
  private short getKeyStatus(byte[] apduBuffer, short off) {
    Util.arrayCopyNonAtomic(keyPath, (short) 0, apduBuffer, off, keyPathLen);
    return keyPathLen;
  }

  /**
   * Processes the VERIFY PIN command. Requires a secure channel to be already open. If a PIN longer or shorter than 6
   * digits is provided, the method will still proceed with its verification and will decrease the remaining tries
   * counter.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void verifyPIN(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len)) {
      ISOException.throwIt((short)((short) 0x63c0 | (short) pin.getTriesRemaining()));
    }
  }

  /**
   * Processes the CHANGE PIN command. Requires a secure channel to be already open and the user PIN to be verified. All
   * PINs have a fixed format which is verified by this method.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void changePIN(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    switch(apduBuffer[ISO7816.OFFSET_P1]) {
      case CHANGE_PIN_P1_USER_PIN:
        changeUserPIN(apduBuffer, len);
        break;
      case CHANGE_PIN_P1_PUK:
        changePUK(apduBuffer, len);
        break;
      case CHANGE_PIN_P1_PAIRING_SECRET:
        changePairingSecret(apduBuffer, len);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        break;
    }
  }

  /**
   * Changes the user PIN. Called internally by CHANGE PIN
   * @param apduBuffer the APDU buffer
   * @param len the data length
   */
  private void changeUserPIN(byte[] apduBuffer, byte len) {
    if (!(len == PIN_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    pin.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
    pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len);
  }

  /**
   * Changes the PUK. Called internally by CHANGE PIN
   * @param apduBuffer the APDU buffer
   * @param len the data length
   */
  private void changePUK(byte[] apduBuffer, byte len) {
    if (!(len == PUK_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    puk.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
  }

  /**
   * Changes the pairing secret. Called internally by CHANGE PIN
   * @param apduBuffer the APDU buffer
   * @param len the data length
   */
  private void changePairingSecret(byte[] apduBuffer, byte len) {
    if (len != SecureChannel.SC_SECRET_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    secureChannel.updatePairingSecret(apduBuffer, ISO7816.OFFSET_CDATA);
  }

  /**
   * Processes the UNBLOCK PIN command. Requires a secure channel to be already open and the PIN to be blocked. The PUK
   * and the new PIN are sent in the same APDU with no separator. This is possible because the PUK is exactly 12 digits
   * long and the PIN is 6 digits long. If the data is not in the correct format (i.e: anything other than 18 digits),
   * PUK verification is not attempted, so the remaining tries counter of the PUK is not decreased.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void unblockPIN(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

    if (pin.getTriesRemaining() != 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

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

  /**
   * Processes the LOAD KEY command. Requires a secure channel to be already open and the PIN to be verified. The key
   * being loaded will be treated as the master key. If the key is not in extended format (i.e: does not contain a chain
   * code) no further derivation will be possible. Loading a key resets the current key path and the loaded key becomes
   * the one used for signing. Transactions are used to make sure that either all key components are loaded correctly
   * or none is loaded at all.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void loadKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // Sanitize P1 input
    byte exportability = (byte) MASTERSEED_EMPTY;
    switch(apduBuffer[ISO7816.OFFSET_P2]) {
      case (byte) 0:
        exportability = (byte) MASTERSEED_NOT_EXPORTABLE;
        break;
      case (byte) 1:
        exportability = (byte) MASTERSEED_EXPORTABLE;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        break;
    }

    switch (apduBuffer[ISO7816.OFFSET_P1])  {
      case LOAD_KEY_P1_SEED:
        loadSeed(apduBuffer);
        masterSeedStatus = exportability; // Only save seed exportability after seed successfully loaded
        break;
      case LOAD_KEY_P1_EC: // Deprecated by Grid+ - require master seed
      case LOAD_KEY_P1_EXT_EC: // Deprecated by Grid+ - require master seed
      default:
        masterSeedStatus = MASTERSEED_EMPTY;
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        break;
    }

    pinlessPathLen = 0;
    generateKeyUIDAndRespond(apdu, apduBuffer);
  }

  /**
   * Generates the Key UID from the current master public key and responds to the command.
   *
   * @param apdu the JCRE-owned APDU object.
   * @param apduBuffer the APDU buffer
   */
  private void generateKeyUIDAndRespond(APDU apdu, byte[] apduBuffer) {
    short pubLen = masterPublic.getW(apduBuffer, (short) 0);
    crypto.sha256.doFinal(apduBuffer, (short) 0, pubLen, keyUID, (short) 0);
    Util.arrayCopyNonAtomic(keyUID, (short) 0, apduBuffer, SecureChannel.SC_OUT_OFFSET, KEY_UID_LENGTH);
    secureChannel.respond(apdu, KEY_UID_LENGTH, ISO7816.SW_NO_ERROR);
  }

  /**
   * Resets the status of the keys. This method must be called immediately before committing the transaction where key
   * manipulation has happened to be sure that the state is always consistent.
   */
  private void resetKeyStatus() {
    parentPrivateKey.clearKey();
    secp256k1.setCurveParameters(parentPrivateKey);
    keyPathLen = 0;
  }

  /**
   * Called internally by the loadKey method to load a key in the TLV format. The presence of the public key is optional.
   * The presence of the chain code determines whether the key is extended or not.
   *
   * @param apduBuffer the APDU buffer
   */
  private void loadKeyPair(byte[] apduBuffer) {
    short pubOffset = (short)(ISO7816.OFFSET_CDATA + (apduBuffer[(short) (ISO7816.OFFSET_CDATA + 1)] == (byte) 0x81 ? 3 : 2));
    short privOffset = (short)(pubOffset + apduBuffer[(short)(pubOffset + 1)] + 2);
    short chainOffset = (short)(privOffset + apduBuffer[(short)(privOffset + 1)] + 2);

    // Do not allow overwriting of master seeds - require that the user call REMOVE_KEY first
    if (masterSeedStatus != MASTERSEED_EMPTY) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    if (apduBuffer[pubOffset] != TLV_PUB_KEY) {
      chainOffset = privOffset;
      privOffset = pubOffset;
      pubOffset = -1;
    }

    if (!((apduBuffer[ISO7816.OFFSET_CDATA] == TLV_KEY_TEMPLATE) && (apduBuffer[privOffset] == TLV_PRIV_KEY)))  {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();

    try {
      isExtended = (apduBuffer[chainOffset] == TLV_CHAIN_CODE);

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
        pubLen = secp256k1.derivePublicKey(masterPrivate, apduBuffer, pubOffset);
      }

      masterPublic.setW(apduBuffer, pubOffset, pubLen);
      publicKey.setW(apduBuffer, pubOffset, pubLen);
    } catch (CryptoException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    resetKeyStatus();
    JCSystem.commitTransaction();
  }

  /**
   * Called internally by the loadKey method to load a key from a sequence of 64 bytes, supposedly generated according
   * to the algorithms described in the BIP39 specifications. This way of loading keys is only supported when public
   * key derivation is available. If not, the public key must be derived off-card and the key must be formatted in the
   * TLV format processed by the loadKeyPair method.
   *
   * @param apduBuffer the APDU buffer
   */
  private void loadSeed(byte[] apduBuffer) {
    if (apduBuffer[ISO7816.OFFSET_LC] != BIP39_SEED_SIZE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    
    // Do not allow overwriting of master seeds - require that the user call REMOVE_KEY first
    if (masterSeedStatus != MASTERSEED_EMPTY) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    JCSystem.beginTransaction();

    // Save the seed before turning it into a master key
    Util.arrayCopy(apduBuffer, (short) ISO7816.OFFSET_CDATA, masterSeed, (short) 0, BIP39_SEED_SIZE);

    crypto.bip32MasterFromSeed(apduBuffer, (short) ISO7816.OFFSET_CDATA, BIP39_SEED_SIZE, apduBuffer, (short) ISO7816.OFFSET_CDATA);

    isExtended = true;

    masterPrivate.setS(apduBuffer, (short) ISO7816.OFFSET_CDATA, CHAIN_CODE_SIZE);
    privateKey.setS(apduBuffer, (short) ISO7816.OFFSET_CDATA, CHAIN_CODE_SIZE);

    Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + CHAIN_CODE_SIZE), masterChainCode, (short) 0, CHAIN_CODE_SIZE);
    Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + CHAIN_CODE_SIZE), chainCode, (short) 0, CHAIN_CODE_SIZE);
    short pubLen = secp256k1.derivePublicKey(masterPrivate, apduBuffer, (short) 0);

    masterPublic.setW(apduBuffer, (short) 0, pubLen);
    publicKey.setW(apduBuffer, (short) 0, pubLen);

    resetKeyStatus();
    JCSystem.commitTransaction();
  }

  /**
   * Processes the DERIVE KEY command. Requires a secure channel to be already open. Unless a PIN-less path exists, t
   * the PIN must be verified as well. The master key must be already loaded and have a chain code. In the happy case
   * this method is quite straightforward, since it takes a sequence of 32-bit big-endian integers and perform key
   * derivations, updating the current key path accordingly.
   *
   * However, since public key derivation might not be supported on card this method also supports the so called
   * assisted derivation scheme. In this scheme the client first sends a single 32-bit big-endian integer. The cards
   * derives the new private key and by taking advantage the EC-DH algorithm returns the X of the public key along with
   * a signature of the SHA-256 hash of a fixed message ("STATUS KEY DERIVATION" in ASCII). The client must then
   * calculate the two possible Y and try to verify the signature with each of the 2 candidate public keys. The public
   * key which correctly verifies the signature is the real one and must be uploaded (as an uncompressed point) through
   * this command again. At this point the current key path is updated and the derived key can be used for signing.
   *
   * In all cases transactions are used to make sure that the current key is always complete (private, chain and public
   * components are coherent) and the key path matches the actual status of the card. This makes recovery from a sudden
   * power loss easy.
   *
   * When the reset flag is set and the data is empty, the assisted key derivation flag is ignored, since in this case
   * no derivation is done and the master key becomes the current key.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void deriveKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short len = secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    doDerive(apduBuffer, (short) 0, len, apduBuffer[ISO7816.OFFSET_P1], true);
  }

  /**
   * Internal derivation function, called by DERIVE KEY and EXPORT KEY
   * @param apduBuffer the APDU buffer
   * @param off the offset in the APDU buffer relative to the data field
   * @param len the len of the path
   * @param source derivation source
   * @param makeCurrent whether the results should be saved or not
   */
  private void doDerive(byte[] apduBuffer, short off, short len, byte source, boolean makeCurrent) {
    if (!isExtended) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short newPathLen;
    short pathLenOff;
    ECPublicKey sourcePub;
    ECPrivateKey sourcePriv;
    byte[] sourceChain;

    switch (source) {
      case DERIVE_P1_SOURCE_MASTER:
        if (len == 0) {
          resetToMaster(apduBuffer);
          return;
        }

        newPathLen = len;
        sourcePriv = masterPrivate;
        sourcePub = masterPublic;
        sourceChain = masterChainCode;
        pathLenOff = 0;
        break;
      case DERIVE_P1_SOURCE_PARENT:
        if (!parentPrivateKey.isInitialized()) {
          ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        if (len == 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        newPathLen = (short) (keyPathLen + len - 4);
        sourcePriv = parentPrivateKey;
        sourcePub = parentPublicKey;
        sourceChain = parentChainCode;
        pathLenOff = (short) (keyPathLen - 4);
        break;
      case DERIVE_P1_SOURCE_CURRENT:
        if (len == 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        newPathLen = (short) (keyPathLen + len);
        sourcePriv = privateKey;
        sourcePub = publicKey;
        sourceChain = chainCode;
        pathLenOff = keyPathLen;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return;
    }

    if (((short) (len % 4) != 0) || (newPathLen > keyPath.length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short pathOff = (short) (ISO7816.OFFSET_CDATA + off);
    short scratchOff = (short) (pathOff + len);
    short dataOff = (short) (scratchOff + Crypto.KEY_DERIVATION_SCRATCH_SIZE);

    short pubKeyOff = (short) (dataOff + sourcePriv.getS(apduBuffer, dataOff));
    pubKeyOff = Util.arrayCopyNonAtomic(sourceChain, (short) 0, apduBuffer, pubKeyOff, CHAIN_CODE_SIZE);

    if (!crypto.bip32IsHardened(apduBuffer, ISO7816.OFFSET_CDATA)) {
      sourcePub.getW(apduBuffer, pubKeyOff);
    } else {
      apduBuffer[pubKeyOff] = 0;
    }

    for (short i = pathOff; i < scratchOff; i += 4) {
      if (i > pathOff) {
        Util.arrayCopyNonAtomic(derivationOutput, (short) 0, apduBuffer, dataOff, (short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE));

        if (!crypto.bip32IsHardened(apduBuffer, i)) {
          secp256k1.derivePublicKey(apduBuffer, dataOff, apduBuffer, pubKeyOff);
        } else {
          apduBuffer[pubKeyOff] = 0;
        }
      }

      if (!crypto.bip32CKDPriv(apduBuffer, i, apduBuffer, scratchOff, apduBuffer, dataOff, derivationOutput, (short) 0)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
    }

    if (makeCurrent) {
      JCSystem.beginTransaction();

      parentPrivateKey.setS(apduBuffer, dataOff, Crypto.KEY_SECRET_SIZE);
      Util.arrayCopy(apduBuffer, (short)(dataOff + Crypto.KEY_SECRET_SIZE), parentChainCode, (short) 0, CHAIN_CODE_SIZE);

      if (apduBuffer[pubKeyOff] == 0x04) {
        parentPublicKey.setW(apduBuffer, pubKeyOff, Crypto.KEY_PUB_SIZE);
      } else {
        secp256k1.derivePublicKey(parentPrivateKey, apduBuffer, scratchOff);
        parentPublicKey.setW(apduBuffer, scratchOff, Crypto.KEY_PUB_SIZE);
      }

      privateKey.setS(derivationOutput, (short) 0, Crypto.KEY_SECRET_SIZE);
      Util.arrayCopy(derivationOutput, Crypto.KEY_SECRET_SIZE, chainCode, (short) 0, CHAIN_CODE_SIZE);
      secp256k1.derivePublicKey(privateKey, apduBuffer, scratchOff);
      publicKey.setW(apduBuffer, scratchOff, Crypto.KEY_PUB_SIZE);

      Util.arrayCopy(apduBuffer, pathOff, keyPath, pathLenOff, len);
      keyPathLen = newPathLen;
      JCSystem.commitTransaction();
    }
  }

  /**
   * Resets to master key
   *
   * @param apduBuffer the APDU buffer
   */
  private void resetToMaster(byte[] apduBuffer) {
    resetKeyStatus();
    masterPrivate.getS(apduBuffer, ISO7816.OFFSET_CDATA);
    privateKey.setS(apduBuffer, ISO7816.OFFSET_CDATA, Crypto.KEY_SECRET_SIZE);
    masterPublic.getW(apduBuffer, ISO7816.OFFSET_CDATA);
    publicKey.setW(apduBuffer, ISO7816.OFFSET_CDATA, Crypto.KEY_PUB_SIZE);
    Util.arrayCopyNonAtomic(masterChainCode, (short) 0, chainCode, (short) 0, CHAIN_CODE_SIZE);
  }

  /**
   * Generates a mnemonic phrase according to the BIP39 specifications. Requires an open secure channel. Since embedding
   * the strings in the applet would be unreasonable, the data returned is actually a sequence of 16-bit big-endian
   * integers with values ranging from 0 to 2047. These numbers should be used by the client as indexes in their own
   * string tables which is used to actually generate the mnemonic phrase.
   *
   * The P1 parameter is the length of the checksum which indirectly also defines the length of the secret and finally
   * the number of generated words. Although using the length of the checksum as the defining parameter (as opposed to
   * the word count for example) might seem peculiar, this is done because it's valid values are strictly in the
   * inclusive range from 4 to 8 which makes it easy to validate input.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void generateMnemonic(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    short csLen = apduBuffer[ISO7816.OFFSET_P1];

    if (csLen < GENERATE_MNEMONIC_P1_CS_MIN || csLen > GENERATE_MNEMONIC_P1_CS_MAX)  {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    short entLen = (short) (csLen * 4);
    crypto.random.generateData(apduBuffer, GENERATE_MNEMONIC_TMP_OFF, entLen);
    crypto.sha256.doFinal(apduBuffer, GENERATE_MNEMONIC_TMP_OFF, entLen, apduBuffer, (short)(GENERATE_MNEMONIC_TMP_OFF + entLen));
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

    secureChannel.respond(apdu, (short) (outOff - SecureChannel.SC_OUT_OFFSET), ISO7816.SW_NO_ERROR);
  }

  /**
   * Logically shifts the given short to the right. Used internally by the generateMnemonic method. This method exists
   * because a simple logical right shift using shorts would most likely work on the actual target (which does math on
   * shorts) but not on the simulator since a negative short would first be extended to 32-bit, shifted and then cut
   * back to 16-bit, doing the equivalent of an arithmetic shift. Simply masking by 0x0000FFFF before shifting is not an
   * option because the code would not convert to CAP file (because of int usage). Since this method works on both
   * JavaCard and simulator and it is not invoked very often, the performance hit is non-existent.
   *
   * @param v value to shift
   * @param amount amount
   * @return logically right shifted value
   */
  private short logicrShift(short v, short amount) {
    if (amount == 0) return v; // short circuit on 0
    short tmp = (short) (v & 0x7fff);

    if (tmp == v) {
      return (short) (v >>> amount);
    }

    tmp = (short) (tmp >>> amount);

    return (short) ((short)((short) 0x4000 >>> (short) (amount - 1)) | tmp);
  }

  /**
   * Processes the REMOVE KEY command. Removes the master key and all derived keys. Secure Channel and PIN
   * authentication are required.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void removeKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    keyPathLen = 0;
    pinlessPathLen = 0;
    isExtended = false;
    privateKey.clearKey();
    publicKey.clearKey();
    masterPrivate.clearKey();
    masterPublic.clearKey();
    parentPrivateKey.clearKey();
    parentPublicKey.clearKey();
    pinlessPrivateKey.clearKey();
    pinlessPublicKey.clearKey();
    resetCurveParameters();
    masterSeedStatus = MASTERSEED_EMPTY;
    Util.arrayFillNonAtomic(masterSeed, (short) 0, (short) masterSeed.length, (byte) 0);
    Util.arrayFillNonAtomic(chainCode, (short) 0, (short) chainCode.length, (byte) 0);
    Util.arrayFillNonAtomic(parentChainCode, (short) 0, (short) parentChainCode.length, (byte) 0);
    Util.arrayFillNonAtomic(masterChainCode, (short) 0, (short) masterChainCode.length, (byte) 0);
    Util.arrayFillNonAtomic(keyPath, (short) 0, (short) keyPath.length, (byte) 0);
    Util.arrayFillNonAtomic(pinlessPath, (short) 0, (short) pinlessPath.length, (byte) 0);
  }

  /**
   * Processes the GENERATE KEY command. Requires an open Secure Channel and PIN authentication. The generated keys are
   * extended and can be used with key derivation. They are not however generated according to BIP39, which means they
   * do not have a mnemonic associated.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void generateKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // Sanitize P1 input
    byte exportability = (byte) MASTERSEED_EMPTY;
    switch(apduBuffer[ISO7816.OFFSET_P1]) {
      case (byte) 0:
        exportability = (byte) MASTERSEED_NOT_EXPORTABLE;
        break;
      case (byte) 1:
        exportability = (byte) MASTERSEED_EXPORTABLE;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        break;
    }

    // Generate random seed
    crypto.random.generateData(apduBuffer, ISO7816.OFFSET_CDATA, BIP39_SEED_SIZE);

    // Load the generated seed
    loadSeed(apduBuffer);
    pinlessPathLen = 0;

    // Save seed exportability (this also indicates the seed as valid)
    masterSeedStatus = exportability; // Only save seed exportability after seed successfully loaded

    secureChannel.respond(apdu, BIP39_SEED_SIZE, ISO7816.SW_NO_ERROR);
  }

  /**
   * Processes the DUPLICATE KEY command. The actual processing depends on the subcommand.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void duplicateKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    if (apduBuffer[ISO7816.OFFSET_P1] == DUPLICATE_KEY_P1_ADD_ENTROPY) {
      if (expectedEntropy <= 0) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      secureChannel.oneShotDecrypt(apduBuffer);
      addEntropy(apduBuffer);
      return;
    } else {
      secureChannel.preprocessAPDU(apduBuffer);

      if (!pin.isValidated()) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
    }

    switch(apduBuffer[ISO7816.OFFSET_P1]) {
      case DUPLICATE_KEY_P1_START:
        startDuplication(apduBuffer);
        break;
      case DUPLICATE_KEY_P1_EXPORT:
        short len = exportDuplicate(apduBuffer);
        secureChannel.respond(apdu, len, ISO7816.SW_NO_ERROR);
        break;
      case DUPLICATE_KEY_P1_IMPORT:
        importDuplicate(apduBuffer);
        pinlessPathLen = 0;
        generateKeyUIDAndRespond(apdu, apduBuffer);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        break;
    }
  }

  private void startDuplication(byte[] apduBuffer) {
    if (apduBuffer[ISO7816.OFFSET_LC] != (short) duplicationEncKey.length) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();
    Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, duplicationEncKey, (short) 0, (short) duplicationEncKey.length);
    expectedEntropy = (short) (apduBuffer[ISO7816.OFFSET_P2] - 1);
    JCSystem.commitTransaction();
  }

  private void addEntropy(byte[] apduBuffer) {
    if (apduBuffer[ISO7816.OFFSET_LC] != (short) duplicationEncKey.length) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();
    for (short i = 0; i < (short) duplicationEncKey.length; i++) {
      duplicationEncKey[i] ^= apduBuffer[(short) (ISO7816.OFFSET_CDATA + i)];
    }

    expectedEntropy--;
    JCSystem.commitTransaction();
  }

  private void finalizeDuplicationKey() {
    if (expectedEntropy != 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    expectedEntropy = -1;
  }

  private short exportDuplicate(byte[] apduBuffer) {
    finalizeDuplicationKey();
    crypto.random.generateData(apduBuffer, SecureChannel.SC_OUT_OFFSET, Crypto.AES_BLOCK_SIZE);
    short off = (short) (SecureChannel.SC_OUT_OFFSET + Crypto.AES_BLOCK_SIZE);
    Util.arrayCopyNonAtomic(apduBuffer, SecureChannel.SC_OUT_OFFSET, apduBuffer, off, Crypto.AES_BLOCK_SIZE);
    off += Crypto.AES_BLOCK_SIZE;

    apduBuffer[off++] = TLV_KEY_TEMPLATE;
    short keyTemplateLenOff = off++;

    apduBuffer[off++] = TLV_PRIV_KEY;
    apduBuffer[off] = (byte) masterPrivate.getS(apduBuffer, (short) (off + 1));
    apduBuffer[keyTemplateLenOff] = (byte) (apduBuffer[off] + 2);
    off += (short) (apduBuffer[off] + 1);

    if (isExtended) {
      apduBuffer[off++] = TLV_CHAIN_CODE;
      apduBuffer[off++] = CHAIN_CODE_SIZE;
      Util.arrayCopyNonAtomic(masterChainCode, (short) 0, apduBuffer, off, CHAIN_CODE_SIZE);
      apduBuffer[keyTemplateLenOff] += (byte) (CHAIN_CODE_SIZE + 2);
      off += CHAIN_CODE_SIZE;
    }

    return (short) (Crypto.AES_BLOCK_SIZE + crypto.oneShotAES(Cipher.MODE_ENCRYPT, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + Crypto.AES_BLOCK_SIZE), off, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + Crypto.AES_BLOCK_SIZE), duplicationEncKey, (short) 0));
  }

  private void importDuplicate(byte[] apduBuffer) {
    finalizeDuplicationKey();
    short len = crypto.oneShotAES(Cipher.MODE_DECRYPT, apduBuffer, ISO7816.OFFSET_CDATA, (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xff), apduBuffer, ISO7816.OFFSET_CDATA, duplicationEncKey, (short) 0);
    apduBuffer[ISO7816.OFFSET_LC] = (byte) len;
    loadKeyPair(apduBuffer);
  }

  /**
   * Processes the SIGN command. Requires a secure channel to open and either the PIN to be verified or the PIN-less key
   * path to be the current key path. This command supports signing  a precomputed 32-bytes hash. The signature is
   * generated using the current keys, so if no keys are loaded the command does not work. The result of the execution
   * is not the plain signature, but a TLV object containing the public key which must be used to verify the signature
   * and the signature itself. The client should use this to calculate 'v' and format the signature according to the
   * format required for the transaction to be correctly inserted in the blockchain.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void sign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    boolean usePinless = false;
    boolean derive = false;
    boolean makeCurrent = false;

    ECPrivateKey signingKey;
    ECPublicKey outputKey;

    switch((byte) (apduBuffer[ISO7816.OFFSET_P1] & ~DERIVE_P1_SOURCE_MASK)) {
      case SIGN_P1_CURRENT_KEY:
        signingKey = privateKey;
        outputKey = publicKey;
        break;
      case SIGN_P1_DERIVE:
        signingKey = secp256k1.tmpECPrivateKey;
        outputKey = null;
        derive = true;
        break;
      case SIGN_P1_DERIVE_AND_MAKE_CURRENT:
        signingKey = privateKey;
        outputKey = publicKey;
        derive = true;
        makeCurrent = true;
        break;
      case SIGN_P1_PINLESS:
        usePinless = true;
        signingKey = pinlessPrivateKey;
        outputKey = pinlessPublicKey;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return;
    }

    short len;

    if (usePinless && !secureChannel.isOpen()) {
      len = (short) (apduBuffer[ISO7816.OFFSET_LC] & (short) 0xff);
    } else {
      len = secureChannel.preprocessAPDU(apduBuffer);
    }

    if (usePinless && pinlessPathLen == 0) {
      ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
    }

    if (!((pin.isValidated() || usePinless || isPinless()) && privateKey.isInitialized())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if (derive) {
      short pathLen = (short) (len - MessageDigest.LENGTH_SHA_256);

      if (pathLen <= 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }

      byte derivationSource = (byte) (apduBuffer[ISO7816.OFFSET_P1] & DERIVE_P1_SOURCE_MASK);
      doDerive(apduBuffer, MessageDigest.LENGTH_SHA_256, pathLen, derivationSource, makeCurrent);
    } else {
      if (len != MessageDigest.LENGTH_SHA_256) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }

    apduBuffer[SecureChannel.SC_OUT_OFFSET] = TLV_SIGNATURE_TEMPLATE;
    apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 3)] = TLV_PUB_KEY;
    short outLen = apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 4)] = Crypto.KEY_PUB_SIZE;

    if (outputKey != null) {
      outputKey.getW(apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + 5));
    } else {
      secp256k1.derivePublicKey(derivationOutput, (short) 0, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + 5));
    }

    outLen += 5;
    short sigOff = (short) (SecureChannel.SC_OUT_OFFSET + outLen);

    signature.init(signingKey, Signature.MODE_SIGN);

    outLen += signature.signPreComputedHash(apduBuffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, apduBuffer, sigOff);
    outLen += crypto.fixS(apduBuffer, sigOff);

    apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 1)] = (byte) 0x81;
    apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 2)] = (byte) (outLen - 3);

    if (secureChannel.isOpen()) {
      secureChannel.respond(apdu, outLen, ISO7816.SW_NO_ERROR);
    } else {
      apdu.setOutgoingAndSend(SecureChannel.SC_OUT_OFFSET, outLen);
    }
  }

  /**
   * Processes the SET PINLESS PATH command. Requires an open secure channel and the PIN to be verified. It does not
   * require keys to be loaded or the current key path to be set at a specific value. The data is formatted in the same
   * way as for DERIVE KEY. In case the sequence of integers is empty, the PIN-less path is simply unset, so the master
   * key can never become PIN-less.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void setPinlessPath(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short len = secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if (((short) (len % 4) != 0) || (len > pinlessPath.length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();
    pinlessPathLen = len;
    Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, pinlessPath, (short) 0, len);

    if (pinlessPathLen > 0) {
      doDerive(apduBuffer, (short) 0, len, DERIVE_P1_SOURCE_MASTER, false);
      pinlessPrivateKey.setS(derivationOutput, (short) 0, Crypto.KEY_SECRET_SIZE);
      secp256k1.derivePublicKey(pinlessPrivateKey, apduBuffer, (short) 0);
      pinlessPublicKey.setW(apduBuffer, (short) 0, Crypto.KEY_PUB_SIZE);
    }

    JCSystem.commitTransaction();
  }
  
  /**
   * Processes the EXPORT SEED command. Requires an open secure channel and the PIN to be verified.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void exportSeed(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated() || masterSeedStatus == MASTERSEED_EMPTY) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if (masterSeedStatus != MASTERSEED_EXPORTABLE) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    short off = SecureChannel.SC_OUT_OFFSET;
    apduBuffer[off++] = TLV_SEED;
    apduBuffer[off++] = (byte) BIP39_SEED_SIZE;
    Util.arrayCopyNonAtomic(masterSeed, (short) 0, apduBuffer, off++, BIP39_SEED_SIZE);

    secureChannel.respond(apdu, (short) (2 + BIP39_SEED_SIZE), ISO7816.SW_NO_ERROR);
  }

  /**
   * Processes the EXPORT KEY command. Requires an open secure channel and the PIN to be verified.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void exportKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short dataLen = secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated() || !privateKey.isInitialized()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    boolean withChaincode;
    switch (apduBuffer[ISO7816.OFFSET_P2]) {
      case EXPORT_KEY_P2_PUBLIC_ONLY:
        withChaincode = false;
        break;
      case EXPORT_KEY_P2_PUBLIC_AND_CHAINCODE:
        withChaincode = true;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return;
    }

    byte[] exportPath = keyPath;
    short exportPathOff = (short) 0;
    short exportPathLen = keyPathLen;

    boolean derive = false;
    boolean makeCurrent = false;
    byte derivationSource = (byte) (apduBuffer[ISO7816.OFFSET_P1] & DERIVE_P1_SOURCE_MASK);

    switch ((byte) (apduBuffer[ISO7816.OFFSET_P1] & ~DERIVE_P1_SOURCE_MASK)) {
      case EXPORT_KEY_P1_CURRENT:
        break;
      case EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT:
        makeCurrent = true;
      case EXPORT_KEY_P1_DERIVE:
        derive = true;
        if (derivationSource == DERIVE_P1_SOURCE_MASTER) {
          exportPath = apduBuffer;
          exportPathOff = ISO7816.OFFSET_CDATA;
          exportPathLen = dataLen;
        }
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return;
    }

    if (derive) {
      doDerive(apduBuffer, (short) 0, dataLen, derivationSource, makeCurrent);
    }

    short off = SecureChannel.SC_OUT_OFFSET;

    apduBuffer[off++] = TLV_KEY_TEMPLATE;
    off++;

    short len;

    if (!derive || makeCurrent) {
      apduBuffer[off++] = TLV_PUB_KEY;
      off++;
      len = publicKey.getW(apduBuffer, off);
      apduBuffer[(short) (off - 1)] = (byte) len;
      off += len;
    } else {
      apduBuffer[off++] = TLV_PUB_KEY;
      off++;
      len = secp256k1.derivePublicKey(derivationOutput, (short) 0, apduBuffer, off);
      apduBuffer[(short) (off - 1)] = (byte) len;
      off += len;
    }
    
    if (withChaincode) {
      apduBuffer[off++] = TLV_CHAIN_CODE;
      off++;
      Util.arrayCopyNonAtomic(chainCode, (short) 0, apduBuffer, off, CHAIN_CODE_SIZE);
      len = CHAIN_CODE_SIZE;
      apduBuffer[(short) (off - 1)] = (byte) len;
      off += len;
    }

    len = (short) (off - SecureChannel.SC_OUT_OFFSET);
    apduBuffer[(SecureChannel.SC_OUT_OFFSET + 1)] = (byte) (len - 2);

    secureChannel.respond(apdu, len, ISO7816.SW_NO_ERROR);
  }

  /**
   * Utility method to verify if all the bytes in the buffer between off (included) and off + len (excluded) are digits.
   *
   * @param buffer the buffer
   * @param off the offset to begin checking
   * @param len the length of the data
   * @return whether all checked bytes are digits or not
   */
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

  /**
   * Returns whether the current key path is the same as the one defined as PIN-less or not
   * @return whether the current key path is the same as the one defined as PIN-less or not
   */
  private boolean isPinless() {
    return (pinlessPathLen > 0) && (pinlessPathLen == keyPathLen) && (Util.arrayCompare(keyPath, (short) 0, pinlessPath, (short) 0, keyPathLen) == 0);
  }

  /**
   * Set curve parameters to cleared keys
   */
  private void resetCurveParameters() {
    secp256k1.setCurveParameters(masterPublic);
    secp256k1.setCurveParameters(masterPrivate);

    secp256k1.setCurveParameters(parentPublicKey);
    secp256k1.setCurveParameters(parentPrivateKey);

    secp256k1.setCurveParameters(publicKey);
    secp256k1.setCurveParameters(privateKey);

    secp256k1.setCurveParameters(pinlessPublicKey);
    secp256k1.setCurveParameters(pinlessPrivateKey);
  }
}

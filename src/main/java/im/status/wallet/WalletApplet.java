package im.status.wallet;

import javacard.framework.*;
import javacard.security.*;

/**
 * The applet's main class. All incoming commands a processed by this class.
 */
public class WalletApplet extends Applet {
  static final short APPLICATION_VERSION = (short) 0x0102;

  static final byte INS_GET_STATUS = (byte) 0xF2;
  static final byte INS_VERIFY_PIN = (byte) 0x20;
  static final byte INS_CHANGE_PIN = (byte) 0x21;
  static final byte INS_UNBLOCK_PIN = (byte) 0x22;
  static final byte INS_LOAD_KEY = (byte) 0xD0;
  static final byte INS_DERIVE_KEY = (byte) 0xD1;
  static final byte INS_GENERATE_MNEMONIC = (byte) 0xD2;
  static final byte INS_REMOVE_KEY = (byte) 0xD3;
  static final byte INS_SIGN = (byte) 0xC0;
  static final byte INS_SET_PINLESS_PATH = (byte) 0xC1;
  static final byte INS_EXPORT_KEY = (byte) 0xC2;

  static final byte PUK_LENGTH = 12;
  static final byte PUK_MAX_RETRIES = 5;
  static final byte PIN_LENGTH = 6;
  static final byte PIN_MAX_RETRIES = 3;
  static final byte KEY_PATH_MAX_DEPTH = 10;
  static final byte PAIRING_MAX_CLIENT_COUNT = 5;
  static final byte UID_LENGTH = 16;

  static final short EC_KEY_SIZE = 256;
  static final short CHAIN_CODE_SIZE = 32;
  static final short KEY_UID_LENGTH = 32;
  static final short BIP39_SEED_SIZE = CHAIN_CODE_SIZE * 2;

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
  static final byte DERIVE_P1_SOURCE_MASK = (byte) 0xC0;
  static final byte DERIVE_P1_SOURCE_MASTER = (byte) 0x00;
  static final byte DERIVE_P1_SOURCE_PARENT = (byte) 0x40;
  static final byte DERIVE_P1_SOURCE_CURRENT = (byte) 0x80;

  static final byte DERIVE_P2_KEY_PATH = 0x00;
  static final byte DERIVE_P2_PUBLIC_KEY = 0x01;

  static final byte GENERATE_MNEMONIC_P1_CS_MIN = 4;
  static final byte GENERATE_MNEMONIC_P1_CS_MAX = 8;
  static final byte GENERATE_MNEMONIC_TMP_OFF = SecureChannel.SC_OUT_OFFSET + ((((GENERATE_MNEMONIC_P1_CS_MAX * 32) + GENERATE_MNEMONIC_P1_CS_MAX) / 11) * 2);

  static final byte EXPORT_KEY_P1_ANY = 0x00;
  static final byte EXPORT_KEY_P1_HIGH = 0x01;

  static final byte EXPORT_KEY_P2_PRIVATE_AND_PUBLIC = 0x00;
  static final byte EXPORT_KEY_P2_PUBLIC_ONLY = 0x01;

  static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;

  static final byte TLV_KEY_TEMPLATE = (byte) 0xA1;
  static final byte TLV_PUB_KEY = (byte) 0x80;
  static final byte TLV_PRIV_KEY = (byte) 0x81;
  static final byte TLV_CHAIN_CODE = (byte) 0x82;

  static final byte TLV_KEY_DERIVATION_TEMPLATE = (byte) 0xA2;
  static final byte TLV_PUB_X = (byte) 0x83;

  static final byte TLV_APPLICATION_STATUS_TEMPLATE = (byte) 0xA3;
  static final byte TLV_INT = (byte) 0x02;
  static final byte TLV_BOOL = (byte) 0x01;

  static final byte TLV_APPLICATION_INFO_TEMPLATE = (byte) 0xA4;
  static final byte TLV_UID = (byte) 0x8F;
  static final byte TLV_KEY_UID = (byte) 0x8E;

  private static final byte[] ASSISTED_DERIVATION_HASH = {(byte) 0xAA, (byte) 0x2D, (byte) 0xA9, (byte) 0x9D, (byte) 0x91, (byte) 0x8C, (byte) 0x7D, (byte) 0x95, (byte) 0xB8, (byte) 0x96, (byte) 0x89, (byte) 0x87, (byte) 0x3E, (byte) 0xAA, (byte) 0x37, (byte) 0x67, (byte) 0x25, (byte) 0x0C, (byte) 0xFF, (byte) 0x50, (byte) 0x13, (byte) 0x9A, (byte) 0x2F, (byte) 0x87, (byte) 0xBB, (byte) 0x4F, (byte) 0xCA, (byte) 0xB4, (byte) 0xAE, (byte) 0xC3, (byte) 0xE8, (byte) 0x90};
  private static final byte EXPORT_KEY_HIGH_MASK = (byte) 0xc0;

  private OwnerPIN pin;
  private OwnerPIN puk;
  private byte[] uid;
  private SecureChannel secureChannel;

  private ECPublicKey masterPublic;
  private ECPrivateKey masterPrivate;
  private byte[] masterChainCode;
  private boolean isExtended;

  private ECPublicKey parentPublicKey;
  private ECPrivateKey parentPrivateKey;
  private byte[] parentChainCode;
  private boolean parentValid;

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

  private byte[] keyUID;

  private Crypto crypto;
  private SECP256k1 secp256k1;

  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
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
  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    crypto = new Crypto();
    secp256k1 = new SECP256k1(crypto);

    uid = new byte[UID_LENGTH];
    crypto.random.generateData(uid, (short) 0, UID_LENGTH);

    masterPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EC_KEY_SIZE, false);
    masterPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_KEY_SIZE, false);

    parentPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EC_KEY_SIZE, false);
    parentPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_KEY_SIZE, false);

    publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EC_KEY_SIZE, false);
    privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_KEY_SIZE, false);

    masterChainCode = new byte[CHAIN_CODE_SIZE];
    parentChainCode = new byte[CHAIN_CODE_SIZE];
    chainCode = new byte[CHAIN_CODE_SIZE];
    keyPath = new byte[KEY_PATH_MAX_DEPTH * 4];
    pinlessPath = new byte[KEY_PATH_MAX_DEPTH * 4];

    keyUID = new byte[KEY_UID_LENGTH];

    resetCurveParameters();

    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    short c9Off = (short)(bOffset + bArray[bOffset] + 1); // Skip AID
    c9Off += (short)(bArray[c9Off] + 2); // Skip Privileges and parameter length

    secureChannel = new SecureChannel(PAIRING_MAX_CLIENT_COUNT, bArray, (short) (c9Off + PUK_LENGTH), crypto, secp256k1);

    puk = new OwnerPIN(PUK_MAX_RETRIES, PUK_LENGTH);
    puk.update(bArray, c9Off, PUK_LENGTH);

    Util.arrayFillNonAtomic(bArray, c9Off, PIN_LENGTH, (byte) 0x30);
    pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
    pin.update(bArray, c9Off, PIN_LENGTH);

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
        case INS_SIGN:
          sign(apdu);
          break;
        case INS_SET_PINLESS_PATH:
          setPinlessPath(apdu);
          break;
        case INS_EXPORT_KEY:
          exportKey(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          break;
      }
    } catch(ISOException sw) {
      if (shouldRespond(apdu) && (sw.getReason() != ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED)) {
        secureChannel.respond(apdu, (short) 0, sw.getReason());
      } else {
        throw sw;
      }
    }

    if (shouldRespond(apdu)) {
      secureChannel.respond(apdu, (short) 0, ISO7816.SW_NO_ERROR);
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
    signInProgress = false;
    pin.reset();
    puk.reset();
    secureChannel.reset();

    byte[] apduBuffer = apdu.getBuffer();

    apduBuffer[0] = TLV_APPLICATION_INFO_TEMPLATE;
    apduBuffer[2] = TLV_UID;
    apduBuffer[3] = UID_LENGTH;
    Util.arrayCopyNonAtomic(uid, (short) 0, apduBuffer, (short) 4, UID_LENGTH);
    apduBuffer[(short)(UID_LENGTH + 4)] = TLV_PUB_KEY;
    short keyLength = secureChannel.copyPublicKey(apduBuffer, (short) (UID_LENGTH + 6));
    apduBuffer[(short)(UID_LENGTH + 5)] = (byte) keyLength;
    apduBuffer[(short)(UID_LENGTH + keyLength + 6)] = TLV_INT;
    apduBuffer[(short)(UID_LENGTH + keyLength + 7)] = 2;
    Util.setShort(apduBuffer, (short)(UID_LENGTH + keyLength + 8), APPLICATION_VERSION);
    apduBuffer[(short)(UID_LENGTH + keyLength + 10)] = TLV_INT;
    apduBuffer[(short)(UID_LENGTH + keyLength + 11)] = 1;
    apduBuffer[(short)(UID_LENGTH + keyLength + 12)] = secureChannel.getRemainingPairingSlots();
    apduBuffer[(short)(UID_LENGTH + keyLength + 13)] = TLV_KEY_UID;

    if (privateKey.isInitialized()) {
      apduBuffer[(short)(UID_LENGTH + keyLength + 14)] = KEY_UID_LENGTH;
      Util.arrayCopyNonAtomic(keyUID, (short) 0, apduBuffer, (short)(UID_LENGTH + keyLength + 15), KEY_UID_LENGTH);
      keyLength += KEY_UID_LENGTH;
    } else {
      apduBuffer[(short)(UID_LENGTH + keyLength + 14)] = 0;
    }

    apduBuffer[1] = (byte)(keyLength + UID_LENGTH + 13);
    apdu.setOutgoingAndSend((short) 0, (short)(apduBuffer[1] + 2));
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
    apduBuffer[off++] = 12;
    apduBuffer[off++] = TLV_INT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = pin.getTriesRemaining();
    apduBuffer[off++] = TLV_INT;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = puk.getTriesRemaining();
    apduBuffer[off++] = TLV_BOOL;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = privateKey.isInitialized() ? (byte) 0xFF : (byte) 0x00;
    apduBuffer[off++] = TLV_BOOL;
    apduBuffer[off++] = 1;
    apduBuffer[off++] = secp256k1.hasECPointMultiplication() ? (byte) 0xFF : (byte) 0x00;

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
    if (expectPublicKey) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

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
   * Processes the CHANGE PIN command. Requires a secure channel to be already open and the PIN to be verified. Since
   * the PIN is fixed to a 6-digits format, longer or shorter PINs or PINs containing non-numeric characters will be
   * refused.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void changePIN(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if (!(len == PIN_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    pin.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
    pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len);
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

    short pubLen = masterPublic.getW(apduBuffer, (short) 0);
    crypto.sha256.doFinal(apduBuffer, (short) 0, pubLen, keyUID, (short) 0);
    Util.arrayCopyNonAtomic(keyUID, (short) 0, apduBuffer, SecureChannel.SC_OUT_OFFSET, KEY_UID_LENGTH);
    secureChannel.respond(apdu, KEY_UID_LENGTH, ISO7816.SW_NO_ERROR);
  }

  /**
   * Resets the status of the keys. This method must be called immediately before committing the transaction where key
   * manipulation has happened to be sure that the state is always consistent.
   */
  private void resetKeyStatus(boolean toParent) {
    signInProgress = false;
    expectPublicKey = false;
    parentValid = false;
    keyPathLen = toParent ? (short) (keyPathLen - 4) : 0;
  }

  /**
   * Called internally by the loadKey method to load a key in the TLV format. The presence of the public key is optional
   * if public key derivation is supported on card, otherwise it is mandatory. The presence of a chain code is indicated
   * explicitly through the newExtended argument (which is set depending on the P1 parameter of the command).
   *
   * @param apduBuffer the APDU buffer
   * @param newExtended whether the key to load contains a chain code or not
   */
  private void loadKeyPair(byte[] apduBuffer, boolean newExtended) {
    short pubOffset = (short)(ISO7816.OFFSET_CDATA + (apduBuffer[(short) (ISO7816.OFFSET_CDATA + 1)] == (byte) 0x81 ? 3 : 2));
    short privOffset = (short)(pubOffset + apduBuffer[(short)(pubOffset + 1)] + 2);
    short chainOffset = (short)(privOffset + apduBuffer[(short)(privOffset + 1)] + 2);

    if (apduBuffer[pubOffset] != TLV_PUB_KEY) {
      secp256k1.assertECPointMultiplicationSupport();
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
        pubLen = secp256k1.derivePublicKey(masterPrivate, apduBuffer, pubOffset);
      }

      masterPublic.setW(apduBuffer, pubOffset, pubLen);
      publicKey.setW(apduBuffer, pubOffset, pubLen);
    } catch (CryptoException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    resetKeyStatus(false);
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
    secp256k1.assertECPointMultiplicationSupport();

    if (apduBuffer[ISO7816.OFFSET_LC] != BIP39_SEED_SIZE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    crypto.bip32MasterFromSeed(apduBuffer, (short) ISO7816.OFFSET_CDATA, BIP39_SEED_SIZE, apduBuffer, (short) ISO7816.OFFSET_CDATA);

    JCSystem.beginTransaction();
    isExtended = true;

    masterPrivate.setS(apduBuffer, (short) ISO7816.OFFSET_CDATA, CHAIN_CODE_SIZE);
    privateKey.setS(apduBuffer, (short) ISO7816.OFFSET_CDATA, CHAIN_CODE_SIZE);

    Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + CHAIN_CODE_SIZE), masterChainCode, (short) 0, CHAIN_CODE_SIZE);
    Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + CHAIN_CODE_SIZE), chainCode, (short) 0, CHAIN_CODE_SIZE);
    short pubLen = secp256k1.derivePublicKey(masterPrivate, apduBuffer, (short) 0);

    masterPublic.setW(apduBuffer, (short) 0, pubLen);
    publicKey.setW(apduBuffer, (short) 0, pubLen);

    resetKeyStatus(false);
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

    if (!((pin.isValidated() || (pinlessPathLen > 0)) && isExtended)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    boolean assistedDerivation = (apduBuffer[ISO7816.OFFSET_P1] & DERIVE_P1_ASSISTED_MASK) == DERIVE_P1_ASSISTED_MASK;
    boolean isPublicKey = apduBuffer[ISO7816.OFFSET_P2]  == DERIVE_P2_PUBLIC_KEY;
    boolean isReset = (apduBuffer[ISO7816.OFFSET_P1] & DERIVE_P1_SOURCE_MASK) == DERIVE_P1_SOURCE_MASTER;
    boolean fromParent = (apduBuffer[ISO7816.OFFSET_P1] & DERIVE_P1_SOURCE_MASK) == DERIVE_P1_SOURCE_PARENT;

    if (fromParent && !parentValid) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }

    if ((isPublicKey != (expectPublicKey && !isReset && !fromParent)) || (isPublicKey && !assistedDerivation)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    if (isPublicKey) {
      JCSystem.beginTransaction();
      publicKey.setW(apduBuffer, ISO7816.OFFSET_CDATA, len);
      expectPublicKey = false;
      keyPathLen += 4;
      parentValid = true;
      JCSystem.commitTransaction();
      return;
    }

    if (((short) (len % 4) != 0) || (assistedDerivation && (len > 4)) || ((short)(len + (isReset ? 0 : keyPathLen)) > keyPath.length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if ((len != 0) && !assistedDerivation) {
      secp256k1.assertECPointMultiplicationSupport();
    }

    short chainEnd = (short) (ISO7816.OFFSET_CDATA + len);

    if (isReset || fromParent) {
      resetKeys(fromParent, apduBuffer, chainEnd);
    }

    signInProgress = false;

    for (short i = ISO7816.OFFSET_CDATA; i < chainEnd; i += 4) {
      JCSystem.beginTransaction();

      copyKeys(privateKey, publicKey, chainCode, parentPrivateKey, parentPublicKey, parentChainCode, apduBuffer, chainEnd);

      if (!crypto.bip32CKDPriv(apduBuffer, i, privateKey, publicKey, chainCode, (short) 0)) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      Util.arrayCopy(apduBuffer, i, keyPath, keyPathLen, (short) 4);

      if (assistedDerivation) {
        expectPublicKey = true;
        outputPublicX(apdu, apduBuffer);
      } else {
        short pubLen = secp256k1.derivePublicKey(privateKey, apduBuffer, chainEnd);
        publicKey.setW(apduBuffer, chainEnd, pubLen);
        keyPathLen += 4;
        parentValid = true;
      }

      JCSystem.commitTransaction();
    }
  }

  /**
   * Outputs the X of the public key for the current private. Called internally by the deriveKey method and used during
   * assisted key derivation.
   *
   * @param apdu the JCRE-owned APDU object.
   * @param apduBuffer the APDU buffer.
   */
  private void outputPublicX(APDU apdu, byte[] apduBuffer) {
    short xLen = secp256k1.derivePublicX(privateKey, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + 4));

    signature.init(privateKey, Signature.MODE_SIGN);
    short sigLen = signature.signPreComputedHash(ASSISTED_DERIVATION_HASH, (short) 0, (short) ASSISTED_DERIVATION_HASH.length, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + xLen + 4));

    apduBuffer[SecureChannel.SC_OUT_OFFSET] = TLV_KEY_DERIVATION_TEMPLATE;
    apduBuffer[(short) (SecureChannel.SC_OUT_OFFSET + 1)] = (byte) (xLen + sigLen + 2);
    apduBuffer[(short) (SecureChannel.SC_OUT_OFFSET + 2)] = TLV_PUB_X;
    apduBuffer[(short) (SecureChannel.SC_OUT_OFFSET + 3)] = (byte) xLen;

    secureChannel.respond(apdu, (short) (xLen + sigLen + 4), ISO7816.SW_NO_ERROR);
  }

  /**
   * Resets the current key and key path to the parent or master key. A transaction is used to make sure this all
   * happens at once. This method is called internally by the deriveKey method.
   *
   * @param toParent resets to the parent key
   * @param buffer a buffer which can be overwritten (currently the APDU buffer)
   * @param offset the offset at which the buffer is free
   */
  private void resetKeys(boolean toParent, byte[] buffer, short offset) {
    ECPrivateKey srcPrivKey = toParent ? parentPrivateKey : masterPrivate;
    ECPublicKey srcPubKey = toParent ? parentPublicKey : masterPublic;
    byte[] srcChainCode = toParent ? parentChainCode : masterChainCode;

    JCSystem.beginTransaction();
    copyKeys(srcPrivKey, srcPubKey, srcChainCode, privateKey, publicKey, chainCode, buffer, offset);
    resetKeyStatus(toParent);
    JCSystem.commitTransaction();
  }

  /**
   * Copys a key set to another one. Requires a transient buffer which can be overwritten.
   *
   * @param srcPrivate source private key
   * @param srcPublic source public key
   * @param srcChain source chain code
   * @param dstPrivate destination private key
   * @param dstPublic destination public key
   * @param dstChain destination chain code
   * @param buffer tmp buffer
   * @param offset tmp buffer offset
   */
  private void copyKeys(ECPrivateKey srcPrivate, ECPublicKey srcPublic, byte[] srcChain, ECPrivateKey dstPrivate, ECPublicKey dstPublic, byte[] dstChain, byte[] buffer, short offset) {
    short pubOff = (short) (offset + srcPrivate.getS(buffer, offset));
    short pubLen = srcPublic.getW(buffer, pubOff);

    Util.arrayCopy(srcChain, (short) 0, dstChain, (short) 0, CHAIN_CODE_SIZE);
    dstPrivate.setS(buffer, offset, CHAIN_CODE_SIZE);
    dstPublic.setW(buffer, pubOff, pubLen);
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

  private void removeKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    keyPathLen = 0;
    pinlessPathLen = 0;
    parentValid = false;
    isExtended = false;
    signInProgress = false;
    expectPublicKey = false;
    privateKey.clearKey();
    publicKey.clearKey();
    masterPrivate.clearKey();
    masterPublic.clearKey();
    parentPrivateKey.clearKey();
    parentPublicKey.clearKey();
    resetCurveParameters();
    Util.arrayFillNonAtomic(chainCode, (short) 0, (short) chainCode.length, (byte) 0);
    Util.arrayFillNonAtomic(parentChainCode, (short) 0, (short) parentChainCode.length, (byte) 0);
    Util.arrayFillNonAtomic(masterChainCode, (short) 0, (short) masterChainCode.length, (byte) 0);
    Util.arrayFillNonAtomic(keyPath, (short) 0, (short) keyPath.length, (byte) 0);
    Util.arrayFillNonAtomic(pinlessPath, (short) 0, (short) pinlessPath.length, (byte) 0);
  }

  /**
   * Processes the SIGN command. Requires a secure channel to open and either the PIN to be verified or the PIN-less key
   * path to be the current key path. This command supports signing data using SHA-256 with possible segmentation over
   * multiple APDUs as well as signing a precomputed 32-bytes hash. The latter option is the actual use case at the
   * moment, since Ethereum signatures actually require Keccak-256 hashes, which are not supported by any version of
   * JavaCard (including 3.0.5 which supports SHA-3 but not Keccak-256 which is slightly different). The signature is
   * generated using the current keys, so if no keys are loaded the command does not work. The result of the execution
   * is not the plain signature, but a TLV object containing the public key which must be used to verify the signature
   * and the signature itself. The client should use this to calculate 'v' and format the signature according to the
   * format required for the transaction to be correctly inserted in the blockchain.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void sign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short len = secureChannel.preprocessAPDU(apduBuffer);

    if (!((pin.isValidated() || isPinless()) && privateKey.isInitialized() && !expectPublicKey)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if ((apduBuffer[ISO7816.OFFSET_P2] & SIGN_P2_FIRST_BLOCK_MASK) == SIGN_P2_FIRST_BLOCK_MASK)  {
      signInProgress = true;
      signature.init(privateKey, Signature.MODE_SIGN);
    } else if (!signInProgress) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    if ((apduBuffer[ISO7816.OFFSET_P2] & SIGN_P2_LAST_BLOCK_MASK) == SIGN_P2_LAST_BLOCK_MASK) {
      signInProgress = false;

      apduBuffer[SecureChannel.SC_OUT_OFFSET] = TLV_SIGNATURE_TEMPLATE;
      apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 3)] = TLV_PUB_KEY;
      short outLen = apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 4)] = (byte) publicKey.getW(apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + 5));

      outLen += 5;
      short sigOff = (short) (SecureChannel.SC_OUT_OFFSET + outLen);

      if ((apduBuffer[ISO7816.OFFSET_P1]) == SIGN_P1_DATA) {
        outLen += signature.sign(apduBuffer, ISO7816.OFFSET_CDATA, len, apduBuffer, sigOff);
      } else if ((apduBuffer[ISO7816.OFFSET_P1]) == SIGN_P1_PRECOMPUTED_HASH) {
        outLen += signature.signPreComputedHash(apduBuffer, ISO7816.OFFSET_CDATA, len, apduBuffer, sigOff);
      } else {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      }

      outLen += crypto.fixS(apduBuffer, sigOff);

      apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 1)] = (byte) 0x81;
      apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 2)] = (byte) (outLen - 3);

      secureChannel.respond(apdu, outLen, ISO7816.SW_NO_ERROR);
    } else {
      signature.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
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
    JCSystem.commitTransaction();
  }

  /**
   * Processes the EXPORT KEY command. Requires an open secure channel and the PIN to be verified. The P1 parameter is
   * an index to which key must be exported from the list of exportable ones. At the moment only the Whisper key with
   * key path m/1/1 is exportable. The key is exported only if the current key path matches the key path of the key to
   * be exported. The public key of the current path can always be exported with P1=0x00 and P2=0x01.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  private void exportKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    secureChannel.preprocessAPDU(apduBuffer);

    if (!pin.isValidated() || !privateKey.isInitialized()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    boolean publicOnly;

    switch (apduBuffer[ISO7816.OFFSET_P2]) {
      case EXPORT_KEY_P2_PRIVATE_AND_PUBLIC:
        publicOnly = false;
        break;
      case EXPORT_KEY_P2_PUBLIC_ONLY:
        publicOnly = true;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return;
    }

    switch (apduBuffer[ISO7816.OFFSET_P1]) {
      case EXPORT_KEY_P1_ANY:
        if (!publicOnly) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        break;
      case EXPORT_KEY_P1_HIGH:
        if (keyPathLen < 4 || ((((byte)(keyPath[(byte)(keyPathLen - 4)] & EXPORT_KEY_HIGH_MASK)) != EXPORT_KEY_HIGH_MASK))){
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return;
    }

    short off = SecureChannel.SC_OUT_OFFSET;

    apduBuffer[off++] = TLV_KEY_TEMPLATE;
    off++;
    apduBuffer[off++] = TLV_PUB_KEY;
    off++;
    short len = publicKey.getW(apduBuffer, off);
    apduBuffer[(short)(off - 1)] = (byte) len;
    off += len;

    if (!publicOnly) {
      apduBuffer[off++] = TLV_PRIV_KEY;
      off++;
      len = privateKey.getS(apduBuffer, off);
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
  }
}

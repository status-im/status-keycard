package im.status.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Implements all methods related to the secure channel as specified in the SECURE_CHANNEL.md document.
 */
public class SecureChannel {
  public static final short SC_KEY_LENGTH = 256;
  public static final short SC_SECRET_LENGTH = 32;
  public static final short PAIRING_KEY_LENGTH = SC_SECRET_LENGTH + 1;
  public static final short SC_BLOCK_SIZE = 16;
  public static final short SC_OUT_OFFSET = ISO7816.OFFSET_CDATA + (SC_BLOCK_SIZE * 2);

  public static final byte INS_OPEN_SECURE_CHANNEL = 0x10;
  public static final byte INS_MUTUALLY_AUTHENTICATE = 0x11;
  public static final byte INS_PAIR = 0x12;
  public static final byte INS_UNPAIR = 0x13;

  public static final byte PAIR_P1_FIRST_STEP = 0x00;
  public static final byte PAIR_P1_LAST_STEP = 0x01;

  private AESKey scEncKey;
  private AESKey scMacKey;
  private Cipher scCipher;
  private Signature scSignature;
  private KeyPair scKeypair;
  private byte[] secret;
  private byte[] pairingSecret;

  /*
   * To avoid overhead, the pairing keys are stored in a plain byte array as sequences of 33-bytes elements. The first
   * byte is 0 if the slot is free and 1 if used. The following 32 bytes are the actual key data.
   */
  private byte[] pairingKeys;

  private short preassignedPairingOffset = -1;
  private boolean mutuallyAuthenticated = false;

  /**
   * Instantiates a Secure Channel. All memory allocations needed for the secure channel are performed here. The keypair
   * used for the EC-DH algorithm is also generated here.
   */
  public SecureChannel(byte pairingLimit, byte[] aPairingSecret, short off) {
    scCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);
    scSignature = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);

    scEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    scMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

    scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
    SECP256k1.setCurveParameters((ECKey) scKeypair.getPrivate());
    SECP256k1.setCurveParameters((ECKey) scKeypair.getPublic());
    scKeypair.genKeyPair();

    secret = JCSystem.makeTransientByteArray((byte)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
    pairingSecret = new byte[SC_SECRET_LENGTH];
    pairingKeys = new byte[(short)(PAIRING_KEY_LENGTH * pairingLimit)];

    Util.arrayCopyNonAtomic(aPairingSecret, off, pairingSecret, (short) 0, SC_SECRET_LENGTH);
  }


  /**
   * Processes the OPEN SECURE CHANNEL command.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  public void openSecureChannel(APDU apdu) {
    preassignedPairingOffset = -1;
    mutuallyAuthenticated = false;

    byte[] apduBuffer = apdu.getBuffer();

    short pairingKeyOff = checkPairingIndexAndGetOffset(apduBuffer[ISO7816.OFFSET_P1]);

    if (pairingKeys[pairingKeyOff] != 1) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    } else {
      pairingKeyOff++;
    }

    Crypto.ecdh.init(scKeypair.getPrivate());
    short len;

    try {
      len = Crypto.ecdh.generateSecret(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer[ISO7816.OFFSET_LC], secret, (short) 0);
    } catch(Exception e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return;
    }

    Crypto.random.generateData(apduBuffer, (short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
    Crypto.sha512.update(secret, (short) 0, len);
    Crypto.sha512.update(pairingKeys, pairingKeyOff, SC_SECRET_LENGTH);
    Crypto.sha512.doFinal(apduBuffer, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);
    scEncKey.setKey(secret, (short) 0);
    scMacKey.setKey(secret, SC_SECRET_LENGTH);
    Util.arrayCopyNonAtomic(apduBuffer, SC_SECRET_LENGTH, secret, (short) 0, SC_BLOCK_SIZE);
    Util.arrayFillNonAtomic(secret, SC_BLOCK_SIZE, SC_SECRET_LENGTH, (byte) 0);
    apdu.setOutgoingAndSend((short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
  }

  /**
   * Processes the MUTUALLY AUTHENTICATE command.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  public void mutuallyAuthenticate(APDU apdu) {
    if (!scEncKey.isInitialized() || mutuallyAuthenticated) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();

    short len = preprocessAPDU(apduBuffer);

    if (len != (short) (SC_SECRET_LENGTH * 2)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    Crypto.sha256.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, SC_SECRET_LENGTH, apduBuffer, ISO7816.OFFSET_CDATA);

    if (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_SECRET_LENGTH), SC_SECRET_LENGTH) != 0) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    mutuallyAuthenticated = true;

    Crypto.random.generateData(apduBuffer, SC_OUT_OFFSET, SC_SECRET_LENGTH);
    Crypto.sha256.doFinal(apduBuffer, SC_OUT_OFFSET, SC_SECRET_LENGTH, apduBuffer, (short) (SC_OUT_OFFSET + SC_SECRET_LENGTH));
    respond(apdu, len, ISO7816.SW_NO_ERROR);
  }

  /**
   * Processes the PAIR command.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  public void pair(APDU apdu) {
    if (isOpen()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();

    if (apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short len;

    if (apduBuffer[ISO7816.OFFSET_P1] == PAIR_P1_FIRST_STEP) {
      len = pairStep1(apduBuffer);
    } else if ((apduBuffer[ISO7816.OFFSET_P1] == PAIR_P1_LAST_STEP) && (preassignedPairingOffset != -1)) {
      len = pairStep2(apduBuffer);
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return;
    }

    apdu.setOutgoingAndSend((short) 0, len);
  }

  /**
   * Performs the first step of pairing. In this step the card solves the challenge sent by the card, thus authenticating
   * itself to the client. At the same time, it creates a challenge for the client. This can only fail if the card has
   * already paired with the maximum allowed amount of clients.
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the reply
   */
  private short pairStep1(byte[] apduBuffer) {
    preassignedPairingOffset = -1;

    for (short i = 0; i < (short) pairingKeys.length; i += PAIRING_KEY_LENGTH) {
      if (pairingKeys[i] == 0) {
        preassignedPairingOffset = i;
        break;
      }
    }

    if (preassignedPairingOffset == -1) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }

    Crypto.sha256.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
    Crypto.sha256.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, SC_SECRET_LENGTH, apduBuffer, (short) 0);
    Crypto.random.generateData(secret, (short) 0, SC_SECRET_LENGTH);
    Util.arrayCopyNonAtomic(secret, (short) 0, apduBuffer, SC_SECRET_LENGTH, SC_SECRET_LENGTH);

    return (SC_SECRET_LENGTH * 2);
  }

  /**
   * Performs the last step of pairing. In this step the card verifies that the client has correctly solved its
   * challenge, authenticating it. It then proceeds to generate the pairing key and returns to the client the data
   * necessary to further establish a secure channel session.
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the reply
   */
  private short pairStep2(byte[] apduBuffer) {
    Crypto.sha256.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
    Crypto.sha256.doFinal(secret, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);

    if (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_SECRET_LENGTH) != 0) {
      preassignedPairingOffset = -1;
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    Crypto.random.generateData(apduBuffer, (short) 1, SC_SECRET_LENGTH);
    Crypto.sha256.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
    Crypto.sha256.doFinal(apduBuffer, (short) 1, SC_SECRET_LENGTH, pairingKeys, (short) (preassignedPairingOffset + 1));
    pairingKeys[preassignedPairingOffset] = 1;
    apduBuffer[0] = (byte) (preassignedPairingOffset / PAIRING_KEY_LENGTH);

    preassignedPairingOffset = -1;

    return (SC_SECRET_LENGTH + 1);
  }

  /**
   * Processes the UNPAIR command. For security reasons the key is not only marked as free but also zero-ed out. This
   * method assumes that all security checks have been performed by the calling method.
   *
   * @param apduBuffer the APDU buffer
   */
  public void unpair(byte[] apduBuffer) {
    short off = checkPairingIndexAndGetOffset(apduBuffer[ISO7816.OFFSET_P1]);
    Util.arrayFillNonAtomic(pairingKeys, off, PAIRING_KEY_LENGTH, (byte) 0);
  }

  /**
   * Decrypts the given APDU buffer. The plaintext is written in-place starting at the ISO7816.OFFSET_CDATA offset. The
   * MAC and padding are stripped. The LC byte is overwritten with the plaintext length. If the MAC cannot be verified
   * the secure channel is reset and the SW 0x6982 is thrown.
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the decrypted
   */
  public short preprocessAPDU(byte[] apduBuffer) {
    if (!isOpen()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    short apduLen = (short)((short) apduBuffer[ISO7816.OFFSET_LC] & 0xff);

    scSignature.init(scMacKey, Signature.MODE_VERIFY);
    scSignature.update(apduBuffer, (short) 0, ISO7816.OFFSET_CDATA);
    scSignature.update(secret, SC_BLOCK_SIZE, (short) (SC_BLOCK_SIZE - ISO7816.OFFSET_CDATA));

    if (!scSignature.verify(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE)) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    scCipher.init(scEncKey, Cipher.MODE_DECRYPT, secret, (short) 0, SC_BLOCK_SIZE);
    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);
    short len = scCipher.doFinal(apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA);

    apduBuffer[ISO7816.OFFSET_LC] = (byte) len;

    return len;
  }

  /**
   * Sends the response to the command. This method always throws an ISOException with the given SW, so nothing can be
   * called after its execution. The response data must be placed starting at the SecureChannel.SC_OUT_OFFSET offset, to
   * leave place for the SecureChannel-specific data at the beginning of the APDU.
   *
   * @param apdu the APDU object
   * @param len the length of the plaintext
   */
  public void respond(APDU apdu, short len, short sw) {
    byte[] apduBuffer = apdu.getBuffer();

    Util.setShort(apduBuffer, (short) 0, sw);

    scCipher.init(scEncKey, Cipher.MODE_ENCRYPT, secret, (short) 0, SC_BLOCK_SIZE);
    len = scCipher.doFinal(apduBuffer, SC_OUT_OFFSET, len, apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE));

    scSignature.init(scMacKey, Signature.MODE_SIGN);
    scSignature.update(apduBuffer, (short) 0, (short) 2);
    scSignature.update(secret, SC_BLOCK_SIZE, (short)(SC_BLOCK_SIZE - 2));
    scSignature.sign(apduBuffer, SC_OUT_OFFSET, len, apduBuffer, ISO7816.OFFSET_CDATA);

    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);

    len += SC_BLOCK_SIZE;
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
    ISOException.throwIt(sw);
  }

  /**
   * Copies the public key used for EC-DH in the given buffer.
   *
   * @param buf the buffer
   * @param off the offset in the buffer
   * @return the length of the public key
   */
  public short copyPublicKey(byte[] buf, short off) {
    ECPublicKey pk = (ECPublicKey) scKeypair.getPublic();
    return pk.getW(buf, off);
  }

  /**
   * Returns whether a secure channel is currently established or not.
   * @return whether a secure channel is currently established or not.
   */
  public boolean isOpen() {
    return scEncKey.isInitialized() && scMacKey.isInitialized() && mutuallyAuthenticated;
  }

  /**
   * Resets the Secure Channel, invalidating the current session. If no session is opened, this does nothing.
   */
  public void reset() {
    scEncKey.clearKey();
    scMacKey.clearKey();
    mutuallyAuthenticated = false;
  }

  /**
   * Returns the offset in the pairingKey byte array of the pairing key with the given index. Throws 0x6A86 if the index
   * is invalid
   *
   * @param idx the index
   * @return the offset
   */
  private short checkPairingIndexAndGetOffset(byte idx) {
    short off = (short) (idx * PAIRING_KEY_LENGTH);

    if (off >= ((short) pairingKeys.length)) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    return off;
  }
}

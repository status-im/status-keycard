package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Implements all methods related to the secure channel as specified in the SECURE_CHANNEL.md document.
 */
public class SecureChannel {
  static final byte ID_CERTIFICATE_EMPTY = (byte) 0x00;
  static final byte ID_CERTIFICATE_LOCKED = (byte) 0xFF;

  // cert = [permissions (2), certified pubKey (65), ECDSA signature from CA (74)]
  static final short ECDSA_MAX_LEN = 74;
  static final short PUBKEY_LEN = 65;
  static final short CERTIFICATE_LEN = (byte)(2 + PUBKEY_LEN + ECDSA_MAX_LEN); 

  public static final short SC_KEY_LENGTH = 256;
  public static final short SC_SECRET_LENGTH = 32;
  public static final short PAIRING_KEY_LENGTH = SC_SECRET_LENGTH + 1;
  public static final short SC_BLOCK_SIZE = Crypto.AES_BLOCK_SIZE;
  public static final short SC_OUT_OFFSET = ISO7816.OFFSET_CDATA + (SC_BLOCK_SIZE * 2);
  public static final short SC_COUNTER_MAX = 100;

  public static final byte INS_OPEN_SECURE_CHANNEL = 0x10;
  public static final byte INS_MUTUALLY_AUTHENTICATE = 0x11;
  public static final byte INS_PAIR = 0x12;
  public static final byte INS_UNPAIR = 0x13;

  public static final byte PAIR_P1_PAIRING_SECRET_1 = 0x00; // Preshared secret based pairing (step 1)
  public static final byte PAIR_P1_PAIRING_SECRET_2 = 0x01; // Preshared secret based pairing (step 2)
  public static final byte PAIR_P1_CERTIFICATE_1 = 0x02; // Certificate based pairing (step 1)
  public static final byte PAIR_P1_CERTIFICATE_2 = 0x03; // Certificate based pairing (step 2)

  // This is the maximum length acceptable for plaintext commands/responses for APDUs in short format
  public static final short SC_MAX_PLAIN_LENGTH = (short) 223;

  // Card identity keys and certificate (for certificate based pairing)
  private KeyPair idKeypair;
  private byte[] idCertificate;
  private byte idCertStatus; // EMPTY or LOCKED
  private ECPublicKey caPublicKey;
  private ECPublicKey clientPublicKey;

  private AESKey scEncKey;
  private AESKey scMacKey;
  private Signature scMac;
  private Signature eccSig;
  private KeyPair scKeypair;
  private byte[] secret;
  private byte[] pairingSecret;
  private byte[] challengeMessage;

  private short scCounter;

  /*
   * To avoid overhead, the pairing keys are stored in a plain byte array as sequences of 33-bytes elements. The first
   * byte is 0 if the slot is free and 1 if used. The following 32 bytes are the actual key data.
   */
  private byte[] pairingKeys;

  private short preassignedPairingOffset = -1;
  private byte remainingSlots;
  private boolean mutuallyAuthenticated = false;

  private Crypto crypto;

  /**
   * Instantiates a Secure Channel. All memory allocations (except pairing secret) needed for the secure channel are
   * performed here. The keypair used for the EC-DH algorithm is also generated here.
   */
  public SecureChannel(byte pairingLimit, Crypto crypto, SECP256k1 secp256k1) {
    this.crypto = crypto;

    idKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
    secp256k1.setCurveParameters((ECKey) idKeypair.getPrivate());
    secp256k1.setCurveParameters((ECKey) idKeypair.getPublic());
    idKeypair.genKeyPair();
    
    caPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    secp256k1.setCurveParameters(caPublicKey);

    idCertificate = new byte[CERTIFICATE_LEN];
    idCertStatus = ID_CERTIFICATE_EMPTY;
    
    clientPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    secp256k1.setCurveParameters(clientPublicKey);

    scMac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
    eccSig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    scEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    scMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

    scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
    secp256k1.setCurveParameters((ECKey) scKeypair.getPrivate());
    secp256k1.setCurveParameters((ECKey) scKeypair.getPublic());
    scKeypair.genKeyPair();

    secret = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
    challengeMessage = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT); // Client salt (32) + Card salt(32)
    pairingKeys = new byte[(short)(PAIRING_KEY_LENGTH * pairingLimit)];
    remainingSlots = pairingLimit;

  }

  /**
   * Initializes the SecureChannel instance with the pairing secret.
   *
   * @param aPairingSecret the pairing secret
   * @param off the offset in the buffer
   */
  public void initSecureChannel(byte[] aPairingSecret, short off) {
    if ((pairingSecret != null) || (challengeMessage != null)) return;

    pairingSecret = new byte[SC_SECRET_LENGTH];
    challengeMessage = new byte[SC_SECRET_LENGTH];
    Util.arrayCopy(aPairingSecret, off, pairingSecret, (short) 0, SC_SECRET_LENGTH);
    scKeypair.genKeyPair();
  }

  /**
   * Decrypts the content of the APDU by generating an AES key using EC-DH. Usable only with specific commands.
   * @param apduBuffer the APDU buffer
   */
  public void oneShotDecrypt(byte[] apduBuffer) {
    crypto.ecdh.init(scKeypair.getPrivate());

    short off = (short)(ISO7816.OFFSET_CDATA + 1);
    try {
      crypto.ecdh.generateSecret(apduBuffer, off, apduBuffer[ISO7816.OFFSET_CDATA], secret, (short) 0);
      off = (short)(off + apduBuffer[ISO7816.OFFSET_CDATA]);
    } catch(Exception e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return;
    }

    scEncKey.setKey(secret, (short) 0);
    crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_DECRYPT, apduBuffer, off, SC_BLOCK_SIZE);
    off = (short)(off + SC_BLOCK_SIZE);

    apduBuffer[ISO7816.OFFSET_LC] = (byte) crypto.aesCbcIso9797m2.doFinal(apduBuffer, off, (short)((short)(apduBuffer[ISO7816.OFFSET_LC] & 0xff) - off + ISO7816.OFFSET_CDATA), apduBuffer, ISO7816.OFFSET_CDATA);
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

    crypto.ecdh.init(scKeypair.getPrivate());
    short len;

    try {
      len = crypto.ecdh.generateSecret(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer[ISO7816.OFFSET_LC], secret, (short) 0);
    } catch(Exception e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return;
    }

    crypto.random.generateData(apduBuffer, (short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
    crypto.sha512.update(secret, (short) 0, len);
    crypto.sha512.update(pairingKeys, pairingKeyOff, SC_SECRET_LENGTH);
    crypto.sha512.doFinal(apduBuffer, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);
    scEncKey.setKey(secret, (short) 0);
    scMacKey.setKey(secret, SC_SECRET_LENGTH);
    Util.arrayCopyNonAtomic(apduBuffer, SC_SECRET_LENGTH, secret, (short) 0, SC_BLOCK_SIZE);
    Util.arrayFillNonAtomic(secret, SC_BLOCK_SIZE, (short) (secret.length - SC_BLOCK_SIZE), (byte) 0);
    apdu.setOutgoingAndSend((short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
  }

  /**
   * Processes the MUTUALLY AUTHENTICATE command.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  public void mutuallyAuthenticate(APDU apdu) {
    if (!scEncKey.isInitialized()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    boolean oldMutuallyAuthenticated = mutuallyAuthenticated;
    mutuallyAuthenticated = true;

    byte[] apduBuffer = apdu.getBuffer();
    short len = preprocessAPDU(apduBuffer);

    if (oldMutuallyAuthenticated) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if (len != SC_SECRET_LENGTH) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    crypto.random.generateData(apduBuffer, SC_OUT_OFFSET, SC_SECRET_LENGTH);
    respond(apdu, len, ISO7816.SW_NO_ERROR);
  }

  /**
   * Processes the IDENTIFY_CARD command. Returns the card public key, and a signature on the
   * challenge salt, to prove ownership of the key.
   * @param apdu the JCRE-owned APDU object.
   */
  public void identifyCard(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    // Ensure the received challenge is appropriate length
    if (apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Copy card ID pubKey to the response buffer
    short responseOffset = (short) ISO7816.OFFSET_CDATA + (short) SC_SECRET_LENGTH;
    short off = responseOffset;
    ECPublicKey pk = (ECPublicKey) idKeypair.getPublic();
    short len = pk.getW(apduBuffer, off);
    off += len;

    // Sign the challenge and copy signature to response buffer
    eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
    len = eccSig.signPreComputedHash(apduBuffer, (short) ISO7816.OFFSET_CDATA, SC_SECRET_LENGTH, apduBuffer, off);
    off += len;

    // Send the response
    apdu.setOutgoingAndSend((short) responseOffset, (short)(off - responseOffset));
  }

  /**
   * Processes the LOAD_CERTS command. Copies the APDU buffer into `certs`.
   * This function expects a DER signature and may only be called once.
   * @param apdu the JCRE-owned APDU object.
   */
  public void loadCert(APDU apdu) {
    short caPubOffset = (short) ISO7816.OFFSET_CDATA;
    short certOffset = (short) (caPubOffset + PUBKEY_LEN);
    short certVerifyLen = CERTIFICATE_LEN - ECDSA_MAX_LEN;

    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    if (idCertStatus != ID_CERTIFICATE_EMPTY) {
      // Card cert may only be set once and never overwritten
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    // Make sure the received certificate is appropriate length
    if (apduBuffer[ISO7816.OFFSET_LC] != (byte) (PUBKEY_LEN + CERTIFICATE_LEN)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    JCSystem.beginTransaction();
    // Save the CA public key
    caPublicKey.setW(apduBuffer, caPubOffset, PUBKEY_LEN);
    
    // Verify the certificate signature against the CA pubkey
    if (false == verifyCertificateCASig(apduBuffer, certOffset)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Save the certificate
    Util.arrayCopy(apduBuffer, certOffset, idCertificate, (short) 0, CERTIFICATE_LEN);

    // Lock the certificate
    idCertStatus = ID_CERTIFICATE_LOCKED;
    JCSystem.commitTransaction();
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

    short len = 0;
    switch (apduBuffer[ISO7816.OFFSET_P1]) {
      case PAIR_P1_PAIRING_SECRET_1:
        len = pairSecret1(apduBuffer);
        break;
      case PAIR_P1_PAIRING_SECRET_2:
        if (preassignedPairingOffset != -1) {
          len = pairSecret2(apduBuffer);
        } else {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        break;
      case PAIR_P1_CERTIFICATE_1:
        len = pairCertificate1(apduBuffer);
        break;
      case PAIR_P1_CERTIFICATE_2:
        if (preassignedPairingOffset != -1) {
          len = pairCertificate2(apduBuffer);
        } else {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return;
    }

    apdu.setOutgoingAndSend((short) 0, len);
  }

  /**
   * Performs the first step of secret based pairing. In this step the card solves the challenge sent by the client, thus authenticating
   * itself to the client. At the same time, it creates a challenge for the client. This can only fail if the card has
   * already paired with the maximum allowed amount of clients.
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the reply
   */
  private short pairSecret1(byte[] apduBuffer) {
    // Make sure input length matches expected
    if (apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Search for next available pairing slot
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

    crypto.sha256.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
    crypto.sha256.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, SC_SECRET_LENGTH, apduBuffer, (short) 0);
    crypto.random.generateData(secret, (short) 0, SC_SECRET_LENGTH);
    Util.arrayCopyNonAtomic(secret, (short) 0, apduBuffer, SC_SECRET_LENGTH, SC_SECRET_LENGTH);

    return (SC_SECRET_LENGTH * 2);
  }

  /**
   * Performs the last step of secret based pairing. In this step the card verifies that the client has correctly solved its
   * challenge, authenticating it. It then proceeds to generate the pairing key and returns to the client the data
   * necessary to further establish a secure channel session.
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the reply
   */
  private short pairSecret2(byte[] apduBuffer) {
    // Make sure input length matches expected
    if (apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    crypto.sha256.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
    crypto.sha256.doFinal(secret, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);

    if (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_SECRET_LENGTH) != 0) {
      preassignedPairingOffset = -1;
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    crypto.random.generateData(apduBuffer, (short) 1, SC_SECRET_LENGTH);
    crypto.sha256.update(pairingSecret, (short) 0, SC_SECRET_LENGTH);
    crypto.sha256.doFinal(apduBuffer, (short) 1, SC_SECRET_LENGTH, pairingKeys, (short) (preassignedPairingOffset + 1));
    pairingKeys[preassignedPairingOffset] = 1;
    remainingSlots--;
    apduBuffer[0] = (byte) (preassignedPairingOffset / PAIRING_KEY_LENGTH);

    preassignedPairingOffset = -1;

    return (SC_SECRET_LENGTH + 1);
  }
  
  /**
   * Performs the first step of certificate based pairing. In this step, the card provides a CA signed certificate
   * of its card ID key, and proves ownership of this key with a signature on a challenge hash. The challenge hash
   * to be signed is computed as the sha256 hash of the client salt (provided by client) and card salt (generated randomly).
   * The card will also include its random salt in the response to the client, so that the client can reproduce the challenge
   * hash and verify the card signature.
   * 
   * clientSalt[32] = random salt provided by the client
   * cardSalt[32] = random salt generated by the card
   * challengeHash[32] = sha256(cardChallenge, clientChallenge)
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the reply
   */
  private short pairCertificate1(byte[] apduBuffer) {
    // Make sure input length matches expected
    if (apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Make sure certificate exisits
    if (idCertStatus != ID_CERTIFICATE_LOCKED) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // Search for next available pairing slot
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

    // Compute APDU field offsets
    short cardSaltOff = 0;
    short idCertificateOff = (short) (cardSaltOff + SC_SECRET_LENGTH);
    short sigOff = (short) (idCertificateOff + CERTIFICATE_LEN);

    // Store client salt in challenge message
    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, challengeMessage, (short) 0, SC_SECRET_LENGTH);

    // Generate random card salt
    crypto.random.generateData(apduBuffer, cardSaltOff, SC_SECRET_LENGTH);
    
    // Append card salt to challenge message
    Util.arrayCopyNonAtomic(apduBuffer, cardSaltOff, challengeMessage, SC_SECRET_LENGTH, SC_SECRET_LENGTH);

    // Copy certificate to response buffer
    Util.arrayCopyNonAtomic(idCertificate, (short) 0, apduBuffer, idCertificateOff, (short) CERTIFICATE_LEN);

    // Compute signature on challenge hash using ID key
    eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
    short len = eccSig.sign(challengeMessage, (short) ISO7816.OFFSET_CDATA, (short) challengeMessage.length, apduBuffer, sigOff);

    // Zero-pad end of signature field (ECDSA sig is variable length, but we send full max size field)
    short padCount = (short) (ECDSA_MAX_LEN - len);
    Util.arrayFillNonAtomic(apduBuffer, (short) (sigOff + len), padCount, (byte) 0);

    // Return total response length
    return (short) (SC_SECRET_LENGTH + CERTIFICATE_LEN + ECDSA_MAX_LEN);
  }

  /**
   * Performs the last step of certificate based pairing. In this step, the client provides a CA signed certificate
   * and its public key, and proves ownership of its key with a signature on a challenge hash. The challenge hash
   * to be signed is computed as the sha256 hash of the client salt (provided by client in previous step) and card salt
   * (provided by card in previous step). The card will also include its random salt in the response to the client,
   * so that the client can reproduce the challenge hash and verify the card signature.
   * 
   * clientSalt[32] = random salt provided by the client
   * cardSalt[32] = random salt generated by the card
   * challengeHash[32] = sha256(cardChallenge, clientChallenge)
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the reply
   */
  private short pairCertificate2(byte[] apduBuffer) {
    // Compute command APDU field offsets
    short clientCertOff = ISO7816.OFFSET_CDATA;
    short clientPubkeyOff = (short) (clientCertOff + 2);
    short clientSigOff = ISO7816.OFFSET_CDATA + CERTIFICATE_LEN;

    // Make sure input length matches expected
    if (apduBuffer[ISO7816.OFFSET_LC] != (byte) (CERTIFICATE_LEN + ECDSA_MAX_LEN)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    
    // Verify the certificate signature against the CA pubkey
    if (false == verifyCertificateCASig(apduBuffer, clientCertOff)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Create temporary public key instance with client private key
    clientPublicKey.setW(apduBuffer, clientPubkeyOff, PUBKEY_LEN);

    // Verify the client's signature on the challenge hash
    eccSig.init(clientPublicKey, Signature.MODE_VERIFY);
    if (false == eccSig.verify(challengeMessage, (short) 0, (short) challengeMessage.length, apduBuffer, clientSigOff, ECDSA_MAX_LEN)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Generate random pairing salt
    crypto.random.generateData(apduBuffer, (short) 1, SC_SECRET_LENGTH);

    // Compute and store pairing key
    // pairingKey[i] = sha256(clientSalt, cardSalt, pairingSalt)
    crypto.sha256.update(challengeMessage, (short) 0, (short) challengeMessage.length);
    crypto.sha256.doFinal(apduBuffer, (short) 1, SC_SECRET_LENGTH, pairingKeys, (short) (preassignedPairingOffset + 1));
    pairingKeys[preassignedPairingOffset] = 1;
    remainingSlots--;
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
    if (pairingKeys[off] == 1) {
      Util.arrayFillNonAtomic(pairingKeys, off, PAIRING_KEY_LENGTH, (byte) 0);
      remainingSlots++;
    }
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

    if (!verifyAESMAC(apduBuffer, apduLen)) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_DECRYPT, secret, (short) 0, SC_BLOCK_SIZE);
    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);
    short len = crypto.aesCbcIso9797m2.doFinal(apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA);

    apduBuffer[ISO7816.OFFSET_LC] = (byte) len;

    return len;
  }

  /**
   * Verifies the AES CBC-MAC, either natively or with a software implementation. Can only be called from the
   * preprocessAPDU method since it expects the input buffer to be formatted in a particular way.
   *
   * @param apduBuffer the APDU buffer
   * @param apduLen the data len
   */
  private boolean verifyAESMAC(byte[] apduBuffer, short apduLen) {
    scMac.init(scMacKey, Signature.MODE_VERIFY);
    scMac.update(apduBuffer, (short) 0, ISO7816.OFFSET_CDATA);
    scMac.update(secret, SC_BLOCK_SIZE, (short) (SC_BLOCK_SIZE - ISO7816.OFFSET_CDATA));

    return scMac.verify(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
  }

  /**
   * Sends the response to the command. This the given SW is appended to the data automatically. The response data must
   * be placed starting at the SecureChannel.SC_OUT_OFFSET offset, to leave place for the SecureChannel-specific data at
   * the beginning of the APDU.
   *
   * @param apdu the APDU object
   * @param len the length of the plaintext
   */
  public void respond(APDU apdu, short len, short sw) {
    byte[] apduBuffer = apdu.getBuffer();

    Util.setShort(apduBuffer, (short) (SC_OUT_OFFSET + len), sw);
    len += 2;

    crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_ENCRYPT, secret, (short) 0, SC_BLOCK_SIZE);
    len = crypto.aesCbcIso9797m2.doFinal(apduBuffer, SC_OUT_OFFSET, len, apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE));

    apduBuffer[0] = (byte) (len + SC_BLOCK_SIZE);

    computeAESMAC(len, apduBuffer);

    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);

    len += SC_BLOCK_SIZE;
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
  }

  /**
   * Computes the AES CBC-MAC, either natively or with a software implementation. Can only be called from the respond
   * method since it expects the input buffer to be formatted in a particular way.
   *
   * @param len the data len
   * @param apduBuffer the APDU buffer
   */
  private void computeAESMAC(short len, byte[] apduBuffer) {
    scMac.init(scMacKey, Signature.MODE_SIGN);
    scMac.update(apduBuffer, (short) 0, (short) 1);
    scMac.update(secret, SC_BLOCK_SIZE, (short) (SC_BLOCK_SIZE - 1));
    scMac.sign(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), len, apduBuffer, ISO7816.OFFSET_CDATA);
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
   * Returns the number of still available pairing slots.
   */
  public byte getRemainingPairingSlots() {
    return remainingSlots;
  }

  /**
   * Called before sending the public key to the client, gives a chance to change keys if needed.
   */
  public void updateSecureChannelCounter() {
    if (scCounter < SC_COUNTER_MAX) {
      scCounter++;
    } else {
      scKeypair.genKeyPair();
      scCounter = 0;
    }
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
   * Updates the pairing secret. Does not affect existing pairings.
   * @param aPairingSecret the buffer
   * @param off the offset
   */
  public void updatePairingSecret(byte[] aPairingSecret, byte off) {
    Util.arrayCopy(aPairingSecret, off, pairingSecret, (short) 0, SC_SECRET_LENGTH);
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
  
  /**
   * Returns true if the supplied certificate is signed by the same CA as the currently loaded card certificate
   *
   * @param certBuf Buffer containing certificate to be verified
   * @param certOff Certificate offset within the buffer
   * @return True if certificate signature is a valid signature from the known CA
   */
  private boolean verifyCertificateCASig(byte[] certBuf, short certOff) {
    short certVerifyLen = CERTIFICATE_LEN - ECDSA_MAX_LEN;

    if (idCertStatus != ID_CERTIFICATE_LOCKED) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // Verify the certificate signature against the CA public key
    eccSig.init(caPublicKey, Signature.MODE_VERIFY);
    return eccSig.verify(certBuf, certOff, certVerifyLen, certBuf, (short) (certOff + certVerifyLen), ECDSA_MAX_LEN);
  }
}

package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;

public class CashApplet extends Applet {
  private static final short SIGN_OUT_OFF = ISO7816.OFFSET_CDATA + MessageDigest.LENGTH_SHA_256;

  private KeyPair keypair;
  private ECPublicKey publicKey;
  private ECPrivateKey privateKey;

  private Crypto crypto;
  private SECP256k1 secp256k1;

  private Signature signature;

  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new CashApplet(bArray, bOffset, bLength);
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
  public CashApplet(byte[] bArray, short bOffset, byte bLength) {
    crypto = new Crypto();
    secp256k1 = new SECP256k1(crypto);

    keypair = new KeyPair(KeyPair.ALG_EC_FP, SECP256k1.SECP256K1_KEY_SIZE);
    publicKey = (ECPublicKey) keypair.getPublic();
    privateKey = (ECPrivateKey) keypair.getPrivate();
    secp256k1.setCurveParameters(publicKey);
    secp256k1.setCurveParameters(privateKey);
    keypair.genKeyPair();

    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signature.init(privateKey, Signature.MODE_SIGN);

    register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  public void process(APDU apdu) throws ISOException {
    apdu.setIncomingAndReceive();

    // Since selection can happen not only by a SELECT command, we check for that separately.
    if (selectingApplet()) {
      selectApplet(apdu);
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();

    try {
      switch (apduBuffer[ISO7816.OFFSET_INS]) {
        case KeycardApplet.INS_SIGN:
          sign(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          break;
      }
    } catch (CryptoException ce) {
      ISOException.throwIt((short)(ISO7816.SW_UNKNOWN | ce.getReason()));
    } catch (Exception e) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
  }

  private void selectApplet(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    apduBuffer[0] = KeycardApplet.TLV_PUB_KEY;
    apduBuffer[1] = (byte) publicKey.getW(apduBuffer, (short) 2);

    apdu.setOutgoingAndSend((short) 0, (short)(apduBuffer[1] + 2));
  }

  private void sign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    apduBuffer[SIGN_OUT_OFF] = KeycardApplet.TLV_SIGNATURE_TEMPLATE;
    apduBuffer[(short) (SIGN_OUT_OFF + 3)] = KeycardApplet.TLV_PUB_KEY;
    short outLen = apduBuffer[(short) (SIGN_OUT_OFF + 4)] = Crypto.KEY_PUB_SIZE;

    publicKey.getW(apduBuffer, (short) (SIGN_OUT_OFF + 5));

    outLen += 5;
    short sigOff = (short) (SIGN_OUT_OFF + outLen);

    outLen += signature.signPreComputedHash(apduBuffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, apduBuffer, sigOff);
    outLen += crypto.fixS(apduBuffer, sigOff);

    apduBuffer[(short) (SIGN_OUT_OFF + 1)] = (byte) 0x81;
    apduBuffer[(short) (SIGN_OUT_OFF + 2)] = (byte) (outLen - 3);

    apdu.setOutgoingAndSend(SIGN_OUT_OFF, outLen);
  }
}

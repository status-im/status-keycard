package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;

/**
 * The applet's main class. All incoming commands a processed by this class.
 */
public class IdentApplet extends Applet {
  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new IdentApplet(bArray, bOffset, bLength);
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
  public IdentApplet(byte[] bArray, short bOffset, byte bLength) {
    SharedMemory.idPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
    SECP256k1.setCurveParameters(SharedMemory.idPrivate);
    SharedMemory.idCert[0] = 0;
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
    if (selectingApplet()) {
      processSelect(apdu);
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();

    switch (apduBuffer[ISO7816.OFFSET_INS]) {
      case KeycardApplet.INS_STORE_DATA:
        processStoreData(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
    }
  }

  private void processSelect(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    if (SharedMemory.idCert[0] == SharedMemory.CERT_VALID) {
      Util.arrayCopyNonAtomic(SharedMemory.idCert, (short) 1, apduBuffer, (short) 0, SharedMemory.CERT_LEN);
      apdu.setOutgoingAndSend((short) 0, SharedMemory.CERT_LEN);
    }

  }

  private void processStoreData(APDU apdu) {
    if (SharedMemory.idCert[0] == SharedMemory.CERT_VALID) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    if (Util.makeShort((byte) 0, apduBuffer[ISO7816.OFFSET_LC]) != (SharedMemory.CERT_LEN + Crypto.KEY_SECRET_SIZE)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, SharedMemory.idCert, (short) 1, SharedMemory.CERT_LEN);
    SharedMemory.idPrivate.setS(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SharedMemory.CERT_LEN), Crypto.KEY_SECRET_SIZE);
    SharedMemory.idCert[0] = SharedMemory.CERT_VALID;
  }
}

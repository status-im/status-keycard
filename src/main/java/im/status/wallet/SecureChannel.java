package im.status.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Implements all methods related to the secure channel as specified in the SECURE_CHANNEL.md document.
 */
public class SecureChannel {
  public static final short SC_KEY_LENGTH = 256;
  public static final short SC_SECRET_LENGTH = 32;
  public static final short SC_BLOCK_SIZE = 16;
  public static final short SC_OUT_OFFSET = ISO7816.OFFSET_CDATA + (SC_BLOCK_SIZE * 2);

  public static final byte INS_OPEN_SECURE_CHANNEL = 0x10;

  private KeyAgreement scAgreement;
  private AESKey scKey;
  private Cipher scCipher;
  private KeyPair scKeypair;
  private byte[] secret;

  /**
   * Instatiates a Secure Channel. All memory allocations needed for the secure channel are peformed here. The keypair
   * used for the EC-DH algorithm is also generated here.
   */
  public SecureChannel() {
    scCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);

    scKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

    scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
    SECP256k1.setCurveParameters((ECKey) scKeypair.getPrivate());
    SECP256k1.setCurveParameters((ECKey) scKeypair.getPublic());
    scKeypair.genKeyPair();

    scAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
    scAgreement.init(scKeypair.getPrivate());

    secret = JCSystem.makeTransientByteArray(SC_SECRET_LENGTH, JCSystem.CLEAR_ON_DESELECT);
  }

  /**
   * Processes the OPEN SECURE CHANNEL command.
   *
   * @param apdu the JCRE-owned APDU object.
   */
  public void openSecureChannel(APDU apdu) {
    apdu.setIncomingAndReceive();
    byte[] apduBuffer = apdu.getBuffer();
    short len = scAgreement.generateSecret(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer[ISO7816.OFFSET_LC], secret, (short) 0);
    Crypto.random.generateData(apduBuffer, (short) 0, SC_SECRET_LENGTH);
    Crypto.sha256.update(secret, (short) 0, len);
    Crypto.sha256.doFinal(apduBuffer, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);
    scKey.setKey(secret, (short) 0);
    apdu.setOutgoingAndSend((short) 0, SC_SECRET_LENGTH);
  }

  /**
   * Decrypts the given APDU buffer. The plaintext is written in-place starting at the ISO7816.OFFSET_CDATA offset. The
   * IV and padding are stripped. The LC byte is overwritten with the plaintext length.
   *
   * @param apduBuffer the APDU buffer
   * @return the length of the decrypted
   */
  public short decryptAPDU(byte[] apduBuffer) {
    short apduLen = (short)((short) apduBuffer[ISO7816.OFFSET_LC] & 0xff);

    scCipher.init(scKey, Cipher.MODE_DECRYPT, apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    short len = scCipher.doFinal(apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA);

    apduBuffer[ISO7816.OFFSET_LC] = (byte) len;

    return len;
  }

  /**
   * Encrypts the APDU buffer. The plaintext must be placed starting at the SecureChannel.SC_OUT_OFFSET offset, to leave
   * place for the SecureChannel-specific data at the beginning of the APDU.
   *
   * @param apduBuffer the APDU buffer
   * @param len the length of the plaintext
   * @return the length of the encrypted APDU
   */
  public short encryptAPDU(byte[] apduBuffer, short len) {
    Crypto.random.generateData(apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    scCipher.init(scKey, Cipher.MODE_ENCRYPT, apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    len = scCipher.doFinal(apduBuffer, SC_OUT_OFFSET, len, apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE));
    return (short)(len + SC_BLOCK_SIZE);
  }

  /**
   * Copies the public key used for EC-DH in the given buffer.
   *
   * @param buf the buffer
   * @param off the offset in the buffer
   * @return the length of the public key
   */
  public short copyPublicKey(byte[] buf, byte off) {
    ECPublicKey pk = (ECPublicKey) scKeypair.getPublic();
    return pk.getW(buf, off);
  }

  /**
   * Returns whether a secure channel is currently established or not.
   * @return whether a secure channel is currently established or not.
   */
  public boolean isOpen() {
    return scKey.isInitialized();
  }
}

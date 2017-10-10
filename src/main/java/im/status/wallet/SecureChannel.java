package im.status.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

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

  public SecureChannel() {
    scCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    scKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

    scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
    ECCurves.setSECP256K1CurveParameters((ECKey) scKeypair.getPrivate());
    ECCurves.setSECP256K1CurveParameters((ECKey) scKeypair.getPublic());
    scKeypair.genKeyPair();

    scAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
    scAgreement.init(scKeypair.getPrivate());

    secret = JCSystem.makeTransientByteArray(SC_SECRET_LENGTH, JCSystem.CLEAR_ON_DESELECT);
  }


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

  public short decryptAPDU(byte[] apduBuffer) {
    short apduLen = (short)((short) apduBuffer[ISO7816.OFFSET_LC] & 0xff);

    scCipher.init(scKey, Cipher.MODE_DECRYPT, apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    short len = scCipher.doFinal(apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA);

    while(apduBuffer[(short)(ISO7816.OFFSET_CDATA+len-1)] != (byte) 0x80) {
      len--;
    }

    len--;

    apduBuffer[ISO7816.OFFSET_LC] = (byte) len;

    return len;
  }

  public short encryptAPDU(byte[] apduBuffer, short len) {
    apduBuffer[(short)(SC_OUT_OFFSET + len)] = (byte) 0x80;
    len++;
    short padding = (short) ((SC_BLOCK_SIZE - (short) (len % SC_BLOCK_SIZE)) % SC_BLOCK_SIZE);
    Util.arrayFillNonAtomic(apduBuffer, (short)(SC_OUT_OFFSET + len), padding, (byte) 0x00);
    len += padding;

    Crypto.random.generateData(apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    scCipher.init(scKey, Cipher.MODE_ENCRYPT, apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    len = scCipher.doFinal(apduBuffer, SC_OUT_OFFSET, len, apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE));
    return (short)(len + SC_BLOCK_SIZE);
  }

  public short copyPublicKey(byte[] buf, byte off) {
    ECPublicKey pk = (ECPublicKey) scKeypair.getPublic();
    return pk.getW(buf, off);
  }

  public boolean isOpen() {
    return scKey.isInitialized();
  }
}

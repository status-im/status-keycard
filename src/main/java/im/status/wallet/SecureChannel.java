package im.status.wallet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class SecureChannel {
  public static final short SC_KEY_SIZE = 256;
  public static final short SC_SECRET_LENGTH = 32;

  public static final byte INS_OPEN_SECURE_CHANNEL = 0x10;

  private KeyAgreement scAgreement;
  private AESKey scKey;
  private Cipher scCipher;
  private KeyPair scKeypair;
  private MessageDigest scMd;
  private RandomData scRandom;
  private byte[] secret;

  public SecureChannel() {
    scRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    scMd = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    scCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    scKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

    scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_SIZE);
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
    scRandom.generateData(apduBuffer, (short) 0, SC_SECRET_LENGTH);
    scMd.update(secret, (short) 0, len);
    scMd.doFinal(apduBuffer, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);
    scKey.setKey(secret, (short) 0);
    apdu.setOutgoingAndSend((short) 0, SC_SECRET_LENGTH);
  }

  public short copyPublicKey(byte[] buf, byte off) {
    ECPublicKey pk = (ECPublicKey) scKeypair.getPublic();
    return pk.getW(buf, off);
  }

  public boolean isOpen() {
    return scKey.isInitialized();
  }
}

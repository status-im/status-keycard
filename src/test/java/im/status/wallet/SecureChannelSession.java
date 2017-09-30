package im.status.wallet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.*;

public class SecureChannelSession {
  public static final int PAYLOAD_MAX_SIZE = 223;

  private byte[] secret;
  private byte[] publicKey;
  private Cipher sessionCipher;
  private SecretKeySpec sessionKey;
  private SecureRandom random;


  public SecureChannelSession(byte[] keyData) {
    try {
      random = new SecureRandom();
      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
      g.initialize(ecSpec, random);

      KeyPair keyPair = g.generateKeyPair();

      publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
      keyAgreement.init(keyPair.getPrivate());

      ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(keyData), ecSpec);
      ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

      keyAgreement.doPhase(cardKey, true);
      secret = MessageDigest.getInstance("SHA1", "BC").digest(keyAgreement.generateSecret());

    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  public ResponseAPDU openSecureChannel(CardChannel apduChannel) throws CardException {
    CommandAPDU openSecureChannel = new CommandAPDU(0x80, SecureChannel.INS_OPEN_SECURE_CHANNEL, 0, 0, publicKey);
    ResponseAPDU response = apduChannel.transmit(openSecureChannel);
    byte[] salt = response.getData();

    try {
      MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
      md.update(secret);
      sessionKey = new SecretKeySpec(md.digest(salt), "AES");
      sessionCipher = Cipher.getInstance("AES/CBC/ISO7816-4Padding", "BC");
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }

    return response;
  }

  public byte[] encryptAPDU(byte[] data) {
    assert data.length <= PAYLOAD_MAX_SIZE;

    if (sessionKey == null) {
      return data;
    }

    try {
      int ivSize = sessionCipher.getBlockSize();
      byte[] iv = new byte[ivSize];
      random.nextBytes(iv);
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

      sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivParameterSpec);
      byte[] encrypted = sessionCipher.doFinal(data);

      byte[] result = new byte[ivSize + encrypted.length];
      System.arraycopy(iv, 0, result, 0, ivSize);
      System.arraycopy(encrypted, 0, result, ivSize, encrypted.length);

      return result;
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  public byte[] decryptAPDU(byte[] data) {
    if (sessionKey == null) {
      return data;
    }

    try {
      int ivSize = sessionCipher.getBlockSize();
      IvParameterSpec ivParameterSpec = new IvParameterSpec(data, 0, ivSize);
      sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivParameterSpec);
      return sessionCipher.doFinal(data, ivSize, data.length - ivSize);
    } catch(Exception e) {
      e.printStackTrace();
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }
}

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

/**
 * Handles a SecureChannel session with the card.
 */
public class SecureChannelSession {
  public static final int PAYLOAD_MAX_SIZE = 223;

  private byte[] secret;
  private byte[] publicKey;
  private Cipher sessionCipher;
  private SecretKeySpec sessionKey;
  private SecureRandom random;

  /**
   * Constructs a SecureChannel session on the client. The client should generate a fresh key pair for each session.
   * The public key of the card is used as input for the EC-DH algorithm. The output is stored as the secret.
   *
   * @param keyData the public key returned by the applet as response to the SELECT command
   */
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
      secret = keyAgreement.generateSecret();

    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  /**
   * Establishes a Secure Channel with the card. The command parameters are the public key generated in the first step.
   * The card returns a secret value which must be appended to the secret previously generated through the EC-DH
   * algorithm. This entire value must be hashed using SHA-256. The hash will be used as the key for an AES CBC cipher
   * using ISO9797-1 Method 2 padding. From this point all further APDU must be sent encrypted and all responses from
   * the card must be decrypted using this secure channel.
   *
   * @param apduChannel the apdu channel
   * @return the card response
   * @throws CardException communication error
   */
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

  /**
   * Encrypts the plaintext data using the session key. The maximum plaintext size is 223 bytes. The returned ciphertext
   * already includes the IV and padding and can be sent as-is in the APDU payload. If the input is an empty byte array
   * the returned data will still contain the IV and padding.
   *
   * @param data the plaintext data
   * @return the encrypted data
   */
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

  /**
   * Decrypts the response from the card using the session key. The returned data is already stripped from IV and padding
   * and can be potentially empty.
   *
   * @param data the ciphetext
   * @return the plaintext
   */
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

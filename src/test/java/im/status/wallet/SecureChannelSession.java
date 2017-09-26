package im.status.wallet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.*;

public class SecureChannelSession {
  private byte[] secret;
  private byte[] publicKey;
  private Cipher sessionCipher;
  private SecretKeySpec sessionKey;

  public SecureChannelSession(byte[] keyData) {
    try {
      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
      g.initialize(ecSpec, new SecureRandom());

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
}

package im.status.wallet;

import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class Crypto {
  private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

  static RandomData random;
  static  MessageDigest sha256;
  static KeyAgreement ecPointMultiplier;

  static void init() {
    try {
      ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
    } catch(CryptoException e) {
      ecPointMultiplier = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    }

    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
  }
}

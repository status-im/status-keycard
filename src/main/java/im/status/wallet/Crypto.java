package im.status.wallet;

import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class Crypto {
  static RandomData random;
  static MessageDigest sha256;


  static void init() {
    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
  }
}

package im.status.wallet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;

/**
 * Utility methods to work with the SECP256k1 curve. This class is not meant to be instantiated, but its init method
 * must be called during applet installation.
 */
public class SECP256k1 {
  static final byte SECP256K1_FP[] = {
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
  };
  static final byte SECP256K1_A[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
  };
  static final byte SECP256K1_B[] = {
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07
  };
  static final byte SECP256K1_G[] = {
      (byte)0x04,
      (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
      (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
      (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
      (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
      (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
      (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
      (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
      (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
  };
  static final byte SECP256K1_R[] = {
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
      (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
      (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
  };

  static final byte SECP256K1_K = (byte)0x01;

  private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

  private KeyAgreement ecPointMultiplier;
  private Crypto crypto;

  /**
   * Allocates objects needed by this class. Must be invoked during the applet installation exactly 1 time.
   */
  SECP256k1(Crypto crypto) {
    this.crypto = crypto;

    try {
      ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
    } catch(CryptoException e) {
      ecPointMultiplier = null;
    }
  }

  /**
   * Sets the SECP256k1 curve parameters to the given ECKey (public or private).
   *
   * @param key the key where the curve parameters must be set
   */
  void setCurveParameters(ECKey key) {
    key.setA(SECP256K1_A, (short) 0x00, (short) SECP256K1_A.length);
    key.setB(SECP256K1_B, (short) 0x00, (short) SECP256K1_B.length);
    key.setFieldFP(SECP256K1_FP, (short) 0x00, (short) SECP256K1_FP.length);
    key.setG(SECP256K1_G, (short) 0x00, (short) SECP256K1_G.length);
    key.setR(SECP256K1_R, (short) 0x00, (short) SECP256K1_R.length);
    key.setK(SECP256K1_K);
  }

  /**
   * Derives the public key from the given private key and outputs it in the pubOut buffer. This is done by multiplying
   * the private key by the G point of the curve.
   *
   * @param privateKey the private key
   * @param pubOut the output buffer for the public key
   * @param pubOff the offset in pubOut
   * @return the length of the public key
   */
  short derivePublicKey(ECPrivateKey privateKey, byte[] pubOut, short pubOff) {
    return multiplyPoint(privateKey, SECP256K1_G, (short) 0, (short) SECP256K1_G.length, pubOut, pubOff);
  }

  /**
   * Derives the X of the public key from the given private key and outputs it in the xOut buffer. This is the plain
   * output of the EC-DH algorithm calculated using the G point of the curve in place of the public key of the second
   * party.
   *
   * @param privateKey the private key
   * @param xOut the output buffer for the X of the public key
   * @param xOff the offset in xOut
   * @return the length of X
   */
  short derivePublicX(ECPrivateKey privateKey, byte[] xOut, short xOff) {
    crypto.ecdh.init(privateKey);
    return crypto.ecdh.generateSecret(SECP256K1_G, (short) 0, (short) SECP256K1_G.length, xOut, xOff);
  }

  /**
   * Multiplies a scalar in the form of a private key by the given point. Internally uses a special version of EC-DH
   * supported since JavaCard 3.0.5 which outputs both X and Y in their uncompressed form.
   *
   * @param privateKey the scalar in a private key object
   * @param point the point to multiply
   * @param pointOff the offset of the point
   * @param pointLen the length of the point
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the length of the data written in the out buffer
   */
  short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out, short outOff) {
    assertECPointMultiplicationSupport();
    ecPointMultiplier.init(privateKey);
    return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
  }

  /**
   * Returns whether the card supports EC point multiplication or not.
   *
   * @return whether the card supports EC point multiplication or not
   */
  boolean hasECPointMultiplication() {
    return ecPointMultiplier != null;
  }

  /**
   * Asserts that EC point multiplication is supported. If not, the 0x6A81 status word is returned by throwing an
   * ISOException.
   */
  void assertECPointMultiplicationSupport() {
    if(!hasECPointMultiplication()) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
  }
}

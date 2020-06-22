package im.status.keycard;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Crypto utilities, mostly BIP32 related. The init method must be called during application installation. This class
 * is not meant to be instantiated.
 */
public class Crypto {
  final static public short AES_BLOCK_SIZE = 16;

  final static short KEY_SECRET_SIZE = 32;
  final static short KEY_PUB_SIZE = 65;
  final static short KEY_DERIVATION_SCRATCH_SIZE = 37;
  final static private short HMAC_OUT_SIZE = 64;

  final static private byte[] MAX_S = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4, (byte) 0x50, (byte) 0x1D, (byte) 0xDF, (byte) 0xE9, (byte) 0x2F, (byte) 0x46, (byte) 0x68, (byte) 0x1B, (byte) 0x20, (byte) 0xA0 };
  final static private byte[] S_SUB = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B, (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41 };

  final static private byte HMAC_IPAD = (byte) 0x36;
  final static private byte HMAC_OPAD = (byte) 0x5c;
  final static private short HMAC_BLOCK_SIZE = (short) 128;

  final static private byte[] KEY_BITCOIN_SEED = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};

  // The below 5 objects can be accessed anywhere from the entire applet
  RandomData random;
  KeyAgreement ecdh;
  MessageDigest sha256;
  MessageDigest sha512;
  Cipher aesCbcIso9797m2;

  private Signature hmacSHA512;
  private HMACKey hmacKey;

  protected byte[] hmacBlock;

  Crypto() {
    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    aesCbcIso9797m2 = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2,false);

    try {
      hmacSHA512 = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
      hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
    } catch (CryptoException e) {
      hmacSHA512 = null;
      hmacBlock = JCSystem.makeTransientByteArray(HMAC_BLOCK_SIZE, JCSystem.CLEAR_ON_RESET);
    }

  }

  boolean bip32IsHardened(byte[] i, short iOff) {
    return (i[iOff] & (byte) 0x80) == (byte) 0x80;
  }

  /**
   * Derives a private key according to the algorithm defined in BIP32. The BIP32 specifications define some checks
   * to be performed on the derived keys. In the very unlikely event that these checks fail this key is not considered
   * to be valid so the derived key is discarded and this method returns false.
   *
   * @param i the buffer containing the key path element (a 32-bit big endian integer)
   * @param iOff the offset in the buffer
   * @return true if successful, false otherwise
   */
  boolean bip32CKDPriv(byte[] i, short iOff, byte[] scratch, short scratchOff, byte[] data, short dataOff, byte[] output, short outOff) {
    short off = scratchOff;

    if (bip32IsHardened(i, iOff)) {
      scratch[off++] = 0;
      off = Util.arrayCopyNonAtomic(data, dataOff, scratch, off, KEY_SECRET_SIZE);
    } else {
      scratch[off++] = ((data[(short) (dataOff + KEY_SECRET_SIZE + KEY_SECRET_SIZE + KEY_PUB_SIZE - 1)] & 1) != 0 ? (byte) 0x03 : (byte) 0x02);
      off = Util.arrayCopyNonAtomic(data, (short) (dataOff + KEY_SECRET_SIZE + KEY_SECRET_SIZE + 1), scratch, off, KEY_SECRET_SIZE);
    }

    off = Util.arrayCopyNonAtomic(i, iOff, scratch, off, (short) 4);

    hmacSHA512(data, (short)(dataOff + KEY_SECRET_SIZE), KEY_SECRET_SIZE, scratch, scratchOff, (short)(off - scratchOff), output, outOff);

    if (ucmp256(output, outOff, SECP256k1.SECP256K1_R, (short) 0) >= 0) {
      return false;
    }

    addm256(output, outOff, data, dataOff, SECP256k1.SECP256K1_R, (short) 0, output, outOff);

    if (isZero256(output, outOff)) {
      return false;
    }

    return true;
  }

  /**
   * Applies the algorithm for master key derivation defined by BIP32 to the binary seed provided as input.
   *
   * @param seed the binary seed
   * @param seedOff the offset of the binary seed
   * @param seedSize the size of the binary seed
   * @param masterKey the output buffer
   * @param keyOff the offset in the output buffer
   */
  void bip32MasterFromSeed(byte[] seed, short seedOff, short seedSize, byte[] masterKey, short keyOff) {
    hmacSHA512(KEY_BITCOIN_SEED, (short) 0, (short) KEY_BITCOIN_SEED.length, seed, seedOff, seedSize, masterKey, keyOff);
  }

  /**
   * Fixes the S value of the signature as described in BIP-62 to avoid malleable signatures. It also fixes the all
   * internal TLV length fields. Returns the number of bytes by which the overall signature length changed (0 or -1).
   *
   * @param sig the signature
   * @param off the offset
   * @return the number of bytes by which the signature length changed
   */
  short fixS(byte[] sig, short off) {
    short sOff = (short) (sig[(short) (off + 3)] + (short) (off + 5));
    short ret = 0;

    if (sig[sOff] == 33) {
      Util.arrayCopyNonAtomic(sig, (short) (sOff + 2), sig, (short) (sOff + 1), (short) 32);
      sig[sOff] = 32;
      sig[(short)(off + 1)]--;
      ret = -1;
    }

    sOff++;

    if (ret == -1 || ucmp256(sig, sOff, MAX_S, (short) 0) > 0) {
      sub256(S_SUB, (short) 0, sig, sOff, sig, sOff);
    }

    return ret;
  }

  /**
   * Calculates the HMAC-SHA512 with the given key and data. Uses a software implementation which only requires SHA-512
   * to be supported on cards which do not have native HMAC-SHA512.
   *
   * @param key the HMAC key
   * @param keyOff the offset of the key
   * @param keyLen the length of the key
   * @param in the input data
   * @param inOff the offset of the input data
   * @param inLen the length of the input data
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   */
  void hmacSHA512(byte[] key, short keyOff, short keyLen, byte[] in, short inOff, short inLen, byte[] out, short outOff) {
    if (hmacSHA512 != null) {
      hmacKey.setKey(key, keyOff, keyLen);
      hmacSHA512.init(hmacKey, Signature.MODE_SIGN);
      hmacSHA512.sign(in, inOff, inLen, out, outOff);
    } else {
      for (byte i = 0; i < 2; i++) {
        Util.arrayFillNonAtomic(hmacBlock, (short) 0, HMAC_BLOCK_SIZE, (i == 0 ? HMAC_IPAD : HMAC_OPAD));

        for (short j = 0; j < keyLen; j++) {
          hmacBlock[j] ^= key[(short)(keyOff + j)];
        }

        sha512.update(hmacBlock, (short) 0, HMAC_BLOCK_SIZE);

        if (i == 0) {
          sha512.doFinal(in, inOff, inLen, out, outOff);
        } else {
          sha512.doFinal(out, outOff, HMAC_OUT_SIZE, out, outOff);
        }
      }
    }
  }

  /**
   * Modulo addition of two 256-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param n the modulo
   * @param nOff the offset of the modulo
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   */
  void addm256(byte[] a, short aOff, byte[] b, short bOff, byte[] n, short nOff, byte[] out, short outOff) {
    if ((add256(a, aOff, b, bOff, out, outOff) != 0) || (ucmp256(out, outOff, n, nOff) > 0)) {
      sub256(out, outOff, n, nOff, out, outOff);
    }
  }

  /**
   * Compares two 256-bit numbers. Returns a positive number if a > b, a negative one if a < b and 0 if a = b.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @return the comparison result
   */
  short ucmp256(byte[] a, short aOff, byte[] b, short bOff) {
    short ai, bi;
    for (short i = 0 ; i < 32; i++) {
      ai = (short)(a[(short)(aOff + i)] & 0x00ff);
      bi = (short)(b[(short)(bOff + i)] & 0x00ff);

      if (ai != bi) {
        return (short)(ai - bi);
      }
    }

    return 0;
  }

  /**
   * Checks if the given 256-bit number is 0.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @return true if a is 0, false otherwise
   */
  boolean isZero256(byte[] a, short aOff) {
    boolean isZero = true;

    for (short i = 0; i < (byte) 32; i++) {
      if (a[(short)(aOff + i)] != 0) {
        isZero = false;
        break;
      }
    }

    return isZero;
  }

  /**
   * Addition of two 256-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the carry of the addition
   */
  short add256(byte[] a, short aOff,  byte[] b, short bOff, byte[] out, short outOff) {
    short outI = 0;
    for (short i = 31 ; i >= 0 ; i--) {
      outI = (short) ((short)(a[(short)(aOff + i)] & 0xFF) + (short)(b[(short)(bOff + i)] & 0xFF) + outI);
      out[(short)(outOff + i)] = (byte)outI;
      outI = (short)(outI >> 8);
    }
    return outI;
  }

  /**
   * Subtraction of two 256-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the carry of the subtraction
   */
  short sub256(byte[] a, short aOff,  byte[] b, short bOff, byte[] out, short outOff) {
    short outI = 0;

    for (short i = 31 ; i >= 0 ; i--) {
      outI = (short)  ((short)(a[(short)(aOff + i)] & 0xFF) - (short)(b[(short)(bOff + i)] & 0xFF) - outI);
      out[(short)(outOff + i)] = (byte)outI ;
      outI = (short)(((outI >> 8) != 0) ? 1 : 0);
    }

    return outI;
  }

  /**
   * Subtraction of two 768-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the carry of the subtraction
   */
  short sub768(byte[] a, short aOff,  byte[] b, short bOff, byte[] out, short outOff) {
    short outI = 0;

    for (short i = 95; i >= 0; i--) {
      outI = (short)  ((short)(a[(short)(aOff + i)] & 0xFF) - (short)(b[(short)(bOff + i)] & 0xFF) - outI);
      out[(short)(outOff + i)] = (byte)outI ;
      outI = (short)(((outI >> 8) != 0) ? 1 : 0);
    }

    return outI;
  }
}

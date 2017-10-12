package opencrypto.jcmathlib;

import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.Signature;

/**
 *
 * @author Petr Svenda
 */
public class ECPoint_Helper {
  // Selected constants missing from older JC API specs
  public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN = (byte) 3;
  public static final byte Signature_ALG_ECDSA_SHA_256 = (byte) 33;

  private final ECConfig ecc;

  byte[] uncompressed_point_arr1 = null;
  byte[] hashArray = null;
  public static final byte NUM_HELPER_ARRAYS = 2;

  // These Bignats helperEC_BN_? are allocated
  Bignat helperEC_BN_A;
  Bignat helperEC_BN_B;
  Bignat helperEC_BN_C;
  Bignat helperEC_BN_D;
  Bignat helperEC_BN_E;
  Bignat helperEC_BN_F;

  // These Bignats are just pointing to some helperEC_BN_? so reasonable naming is preserved yet no need to actually allocated whole Bignat object
  Bignat fnc_add_x_r; // frequent write
  Bignat fnc_add_y_r; // frequent write
  Bignat fnc_add_x_p; // one init, then just read
  Bignat fnc_add_y_p; // one init, then just read
  Bignat fnc_add_x_q; // one init, then just read
  Bignat fnc_add_lambda; // write mod_mul (but only final result)
  Bignat fnc_add_nominator; // frequent write
  Bignat fnc_add_denominator; // frequent write

  Bignat fnc_multiplication_x; // result write
  Bignat fnc_multiplication_y_sq; // frequent write
  Bignat fnc_multiplication_scalar; // write once, read
  Bignat fnc_multiplication_y1; // mostly just read, write inside sqrt_FP
  Bignat fnc_multiplication_y2; // mostly just read, result write
  Bignat fnc_negate_yBN; // mostly just read, result write


  KeyAgreement fnc_multiplication_x_keyAgreement;
  Signature    fnc_SignVerifyECDSA_signEngine;

  public ECPoint_Helper(ECConfig ecCfg) {
    this.ecc = ecCfg;

    helperEC_BN_A = new Bignat(ecc.MAX_POINT_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_A), ecc);
    helperEC_BN_B = new Bignat(ecc.MAX_COORD_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_B), ecc);
    helperEC_BN_C = new Bignat(ecc.MAX_COORD_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_C), ecc);
    helperEC_BN_D = new Bignat(ecc.MAX_COORD_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_D), ecc);
    helperEC_BN_E = new Bignat(ecc.MAX_COORD_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_E), ecc);
    helperEC_BN_F = new Bignat(ecc.MAX_COORD_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_F), ecc);
    // Important: assignment of helper BNs is made according to two criterions:
    // 1. Correctness: same BN must not be assigned to overlapping operations (guarded by lock/unlock)
    // 2. Memory tradeoff: we like to put as few BNs into RAM as possible. So most frequently used BNs for write should be in RAM
    //                      and at the same time we like to have as few BNs in RAM as possible.
    // So think twice before changing the assignments!
    fnc_add_x_r = helperEC_BN_B;
    fnc_add_y_r = helperEC_BN_C;
    fnc_add_x_p = helperEC_BN_D;
    fnc_add_y_p = helperEC_BN_E;
    fnc_add_x_q = helperEC_BN_F;
    fnc_add_nominator = helperEC_BN_B;
    fnc_add_denominator = helperEC_BN_C;
    fnc_add_lambda = helperEC_BN_A;

    fnc_multiplication_scalar = helperEC_BN_F;
    fnc_multiplication_x = helperEC_BN_B;
    fnc_multiplication_y_sq = helperEC_BN_C;
    fnc_multiplication_y1 = helperEC_BN_D;
    fnc_multiplication_y2 = helperEC_BN_B;

    fnc_negate_yBN = helperEC_BN_C;

    uncompressed_point_arr1 = ecc.memAlloc.allocateByteArray((short) (ecc.MAX_POINT_SIZE + 1), ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_uncompressed_point_arr1));

    hashArray = ecc.memAlloc.allocateByteArray(ecc.bnh.hashEngine.getLength(), ecc.memAlloc.getAllocatorType(ObjectAllocator.ECPH_hashArray));

    ecc.FLAG_FAST_EC_MULT_VIA_KA = false; // set true only if succesfully allocated and tested below
    try {
      fnc_multiplication_x_keyAgreement = KeyAgreement.getInstance(KeyAgreement_ALG_EC_SVDP_DH_PLAIN, false);
      fnc_SignVerifyECDSA_signEngine = Signature.getInstance(Signature_ALG_ECDSA_SHA_256, false);
      ecc.FLAG_FAST_EC_MULT_VIA_KA = true;
    }
    catch (Exception ignored) {} // Discard any exception
  }

  /**
   * Erase all values stored in helper objects
   */
  void erase() {
    helperEC_BN_A.erase();
    helperEC_BN_B.erase();
    helperEC_BN_C.erase();
    helperEC_BN_D.erase();
    helperEC_BN_E.erase();
    helperEC_BN_F.erase();
    Util.arrayFillNonAtomic(uncompressed_point_arr1, (short) 0, (short) uncompressed_point_arr1.length, (byte) 0);
  }

  /**
   * Unlocks all helper objects
   */
  public void unlockAll() {
    if (helperEC_BN_A.isLocked()) {
      helperEC_BN_A.unlock();
    }
    if (helperEC_BN_B.isLocked()) {
      helperEC_BN_B.unlock();
    }
    if (helperEC_BN_C.isLocked()) {
      helperEC_BN_C.unlock();
    }
    if (helperEC_BN_D.isLocked()) {
      helperEC_BN_D.unlock();
    }
    if (helperEC_BN_E.isLocked()) {
      helperEC_BN_E.unlock();
    }
    if (helperEC_BN_F.isLocked()) {
      helperEC_BN_F.unlock();
    }
  }


}

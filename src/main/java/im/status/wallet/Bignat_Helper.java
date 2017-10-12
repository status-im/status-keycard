package im.status.wallet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/**
 *
 * @author Petr Svenda
 */
public class Bignat_Helper {
  private final ECConfig ecc;

  /**
   * Helper flag which signalizes that code is executed inside simulator
   * (during tests). Is used to address simulator specific behaviour workaround
   * if required.
   */

  byte[] helper_BN_array1 = null;
  byte[] helper_BN_array2 = null;
  /**
   * Number of pre-allocated helper arrays
   */
  public static final byte NUM_HELPER_ARRAYS = 2;

  byte[] fnc_deep_resize_tmp = null;
  public byte[] fnc_mult_resultArray1 = null;
  byte[] fnc_mult_resultArray2 = null;
  byte[] tmp_array_short = null;

  byte[] fnc_same_value_array1 = null;
  byte[] fnc_same_value_hash = null;


  // These Bignats helper_BN_? are allocated
  Bignat helper_BN_A;
  Bignat helper_BN_B;
  Bignat helper_BN_C;
  Bignat helper_BN_D;
  Bignat helper_BN_E;
  Bignat helper_BN_F;

  // These Bignats are just pointing to some helper_BN_? so reasonable naming is preserved yet no need to actually allocated whole Bignat object
  Bignat fnc_mod_exp_modBN;

  Bignat fnc_mod_add_tmp;
  Bignat fnc_mod_sub_tmp;
  Bignat fnc_mod_sub_tmpOther;
  Bignat fnc_mod_sub_tmpThis;

  Bignat fnc_mod_mult_tmpThis;

  Bignat fnc_mult_mod_tmpThis;
  Bignat fnc_mult_mod_tmp_x;
  Bignat fnc_mult_mod_tmp_mod;

  Bignat fnc_divide_tmpThis;

  Bignat fnc_exponentiation_i;
  Bignat fnc_exponentiation_tmp;

  Bignat fnc_sqrt_p_1;
  Bignat fnc_sqrt_Q;
  Bignat fnc_sqrt_S;
  Bignat fnc_sqrt_tmp;
  Bignat fnc_sqrt_exp;
  Bignat fnc_sqrt_z;

  Bignat fnc_mod_minus_2;

  Bignat fnc_negate_tmp;

  Bignat fnc_int_add_tmpMag;
  Bignat fnc_int_multiply_mod;
  Bignat fnc_int_multiply_tmpThis;
  Bignat fnc_int_divide_tmpThis;

  RSAPublicKey fnc_NmodE_pubKey;
  Cipher fnc_NmodE_cipher;

  public Bignat ONE;
  public Bignat TWO;
  public Bignat THREE;


  // Helper objects for fast multiplication of two large numbers (without modulo)
  KeyPair fnc_mult_keypair = null;
  RSAPublicKey fnc_mult_pubkey_pow2 = null;
  Cipher fnc_mult_cipher = null;
  MessageDigest hashEngine;

  static byte[] CONST_ONE = {0x01};
  static byte[] CONST_TWO = {0x02};

  public Bignat_Helper(ECConfig ecCfg) {
    ecc = ecCfg;

    tmp_array_short = ecc.memAlloc.allocateByteArray((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET); // only 2b RAM for faster add(short)
    fnc_NmodE_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    fnc_NmodE_pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, ecc.MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);

    // Multiplication speedup engines and arrays used by Bignat.mult_RSATrick()
    helper_BN_array1 = ecc.memAlloc.allocateByteArray((short) (ecc.MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_array1));
    helper_BN_array2 = ecc.memAlloc.allocateByteArray((short) (ecc.MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_array2));

    fnc_deep_resize_tmp = helper_BN_array1;
    fnc_mult_resultArray1 = helper_BN_array1;
    fnc_mult_resultArray2 = helper_BN_array2;

    fnc_same_value_array1 = helper_BN_array1;
    fnc_same_value_hash = helper_BN_array2;

    helper_BN_A = new Bignat(ecc.MAX_BIGNAT_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_A), ecc);
    helper_BN_B = new Bignat(ecc.MAX_BIGNAT_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_B), ecc);
    helper_BN_C = new Bignat(ecc.MAX_BIGNAT_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_C), ecc);
    helper_BN_D = new Bignat(ecc.MAX_BIGNAT_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_D), ecc);
    helper_BN_E = new Bignat(ecc.MAX_BIGNAT_SIZE, ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_E), ecc);
    helper_BN_F = new Bignat((short) (ecc.MAX_BIGNAT_SIZE + 2), ecc.memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_F), ecc); // +2 is to correct for infrequent RSA result with two or more leading zeroes

    // BN below are just reassigned allocated helper_BN_? so that same helper_BN_? is not used in parallel (checked by lock() unlock())
    fnc_mod_add_tmp = helper_BN_A;

    fnc_mod_sub_tmpThis = helper_BN_A;
    fnc_mod_sub_tmp = helper_BN_B;
    fnc_mod_sub_tmpOther = helper_BN_C;

    fnc_mult_mod_tmpThis = helper_BN_A;
    fnc_mult_mod_tmp_mod = helper_BN_B;
    fnc_mult_mod_tmp_x = helper_BN_C;

    fnc_exponentiation_tmp = helper_BN_A;
    fnc_exponentiation_i = helper_BN_B;

    fnc_mod_minus_2 = helper_BN_B;

    fnc_negate_tmp = helper_BN_B;

    fnc_sqrt_S = helper_BN_A;
    fnc_sqrt_exp = helper_BN_A;
    fnc_sqrt_p_1 = helper_BN_B;
    fnc_sqrt_Q = helper_BN_C;
    fnc_sqrt_tmp = helper_BN_D;
    fnc_sqrt_z = helper_BN_E;

    fnc_mod_mult_tmpThis = helper_BN_E; // mod_mult is called from  fnc_sqrt => requires helper_BN_E not being locked in fnc_sqrt when mod_mult is called

    fnc_divide_tmpThis = helper_BN_E; // divide is called from  fnc_sqrt => requires helper_BN_E not being locked  in fnc_sqrt when divide is called

    fnc_mod_exp_modBN = helper_BN_F;  // mod_exp is called from  fnc_sqrt => requires helper_BN_F not being locked  in fnc_sqrt when mod_exp is called

    fnc_int_add_tmpMag = helper_BN_A;
    fnc_int_multiply_mod = helper_BN_A;
    fnc_int_multiply_tmpThis = helper_BN_B;
    fnc_int_divide_tmpThis = helper_BN_A;

    // Allocate BN constants always in EEPROM (only reading)
    ONE = new Bignat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, ecc);
    ONE.one();
    TWO = new Bignat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, ecc);
    TWO.two();
    THREE = new Bignat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, ecc);
    THREE.three();

    // Speedup for fast multiplication
    fnc_mult_keypair = new KeyPair(KeyPair.ALG_RSA_CRT, ecc.MULT_RSA_ENGINE_MAX_LENGTH_BITS);
    fnc_mult_keypair.genKeyPair();
    fnc_mult_pubkey_pow2 = (RSAPublicKey) fnc_mult_keypair.getPublic();
    //mult_privkey_pow2 = (RSAPrivateCrtKey) mult_keypair.getPrivate();
    fnc_mult_pubkey_pow2.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
    fnc_mult_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

    hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);


    ecc.FLAG_FAST_MULT_VIA_RSA = false; // set true only if succesfully allocated and tested below
    try { // Subsequent code may fail on some real (e.g., Infineon CJTOP80K) cards - catch exception
      fnc_mult_cipher.init(fnc_mult_pubkey_pow2, Cipher.MODE_ENCRYPT);
      // Try operation - if doesn't work, exception SW_CANTALLOCATE_BIGNAT is emitted
      Util.arrayFillNonAtomic(fnc_mult_resultArray1, (short) 0, (short) fnc_mult_resultArray1.length, (byte) 6);
      fnc_mult_cipher.doFinal(fnc_mult_resultArray1, (short) 0, (short) fnc_mult_resultArray1.length, fnc_mult_resultArray1, (short) 0);
      ecc.FLAG_FAST_MULT_VIA_RSA = true;
    } catch (Exception ignored) {} // discard exception
  }

  /**
   * Erase all values stored in helper objects
   */
  void erase() {
    helper_BN_A.erase();
    helper_BN_B.erase();
    helper_BN_C.erase();
    helper_BN_D.erase();
    helper_BN_E.erase();
    helper_BN_F.erase();

    Util.arrayFillNonAtomic(tmp_array_short, (short) 0, (short) tmp_array_short.length, (byte) 0);
    Util.arrayFillNonAtomic(helper_BN_array1, (short) 0, (short) helper_BN_array1.length, (byte) 0);
    Util.arrayFillNonAtomic(helper_BN_array2, (short) 0, (short) helper_BN_array2.length, (byte) 0);
  }

  /**
   * Unlocks all helper objects
   */
  public void unlockAll() {
    if (helper_BN_A.isLocked()) {
      helper_BN_A.unlock();
    }
    if (helper_BN_B.isLocked()) {
      helper_BN_B.unlock();
    }
    if (helper_BN_C.isLocked()) {
      helper_BN_C.unlock();
    }
    if (helper_BN_D.isLocked()) {
      helper_BN_D.unlock();
    }
    if (helper_BN_E.isLocked()) {
      helper_BN_E.unlock();
    }
    if (helper_BN_F.isLocked()) {
      helper_BN_F.unlock();
    }
  }
}

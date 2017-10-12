package opencrypto.jcmathlib;

import javacard.framework.ISOException;

/**
 * Configure itself to proper lengths and other parameters according to intended length of ECC
 * @author Petr Svenda
 */
public class ECConfig {
  /**
   * The size of speedup engine used for fast modulo exponent computation
   * (must be larger than biggest Bignat used)
   */
  public short MODULO_RSA_ENGINE_MAX_LENGTH_BITS  = (short) 512;
  /**
   * The size of speedup engine used for fast multiplication of large numbers
   * Must be larger than 2x biggest Bignat used
   */
  public short MULT_RSA_ENGINE_MAX_LENGTH_BITS  = (short) 768;
  /**
   * The size of largest integer used in computations
   */
  public short MAX_BIGNAT_SIZE = (short) 65; // ((short) (MODULO_ENGINE_MAX_LENGTH_BITS / 8) + 1);
  /**
   * The size of largest ECC point used
   */
  public short MAX_POINT_SIZE = (short) 64;
  /**
   * The size of single coordinate of the largest ECC point used
   */
  public short MAX_COORD_SIZE = (short) 32; // MAX_POINT_SIZE / 2


  /**
   * If true, fast multiplication of large numbers via RSA engine can be used.
   * Is set automatically after successful allocation of required engines
   */
  public boolean FLAG_FAST_MULT_VIA_RSA = false;
  /**
   * Threshold length in bits of an operand after which speedup with RSA multiplication is used.
   * Schoolbook multiplication is used for shorter operands
   */
  public short FAST_MULT_VIA_RSA_TRESHOLD_LENGTH = (short) 16;

  /**
   * I true, fast multiplication of ECPoints via KeyAgreement can be used
   * Is set automatically after successful allocation of required engines
   */
  public boolean FLAG_FAST_EC_MULT_VIA_KA = false;

  /**
   * Object responsible for easy management of target placement (RAM/EEPROM) fro allocated objects
   */
  public ObjectAllocator memAlloc = null;
  /**
   * Helper structure containing all preallocated objects necessary for Bignat operations
   */
  public Bignat_Helper bnh = null;
  /**
   * Helper structure containing all preallocated objects necessary for ECPoint operations
   */
  public ECPoint_Helper ech = null;

  /**
   * Creates new control structure for requested bit length with all preallocated arrays and engines
   * @param maxECLength maximum length of ECPoint objects supported. The provided value is used to
   *      initialize properly underlying arrays and engines.
   */
  public ECConfig(short maxECLength) {
    // Set proper lengths and other internal settings based on required ECC length
    if (maxECLength <= (short) 256) {
      setECC256Config();
    }
    else if (maxECLength <= (short) 384) {
      setECC384Config();
    }
    else if (maxECLength <= (short) 512) {
      setECC512Config();
    }
    else {
      ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
    }

    //locker.setLockingActive(false); // if required, locking can be disabled
    memAlloc = new ObjectAllocator();
    memAlloc.setAllAllocatorsRAM();
    //if required, memory for helper objects and arrays can be in persistent memory to save RAM (or some tradeoff)
    //ObjectAllocator.setAllAllocatorsEEPROM();  //ObjectAllocator.setAllocatorsTradeoff();

    // Allocate helper objects for BN and EC
    bnh = new Bignat_Helper(this);
    ech = new ECPoint_Helper(this);
  }

  void reset() {
    FLAG_FAST_MULT_VIA_RSA = false;
    FLAG_FAST_EC_MULT_VIA_KA = false;
  }

  public void setECC256Config() {
    reset();
    MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
    MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
    MAX_POINT_SIZE = (short) 64;
    computeDerivedLengths();
  }
  public void setECC384Config() {
    reset();
    MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
    MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
    MAX_POINT_SIZE = (short) 96;
    computeDerivedLengths();
  }
  public void setECC512Config() {
    reset();
    MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
    MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
    MAX_POINT_SIZE = (short) 128;
    computeDerivedLengths();
  }
  public void setECC521Config() {
    reset();
    MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
    MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
    MAX_POINT_SIZE = (short) 129;
    computeDerivedLengths();
  }

  private void computeDerivedLengths() {
    MAX_BIGNAT_SIZE = (short) ((short) (MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8) + 1);
    MAX_COORD_SIZE = (short) (MAX_POINT_SIZE / 2);
  }

  /**
   * Unlocks all logically locked arrays and objects. Useful as recovery after premature end of some operation (e.g., due to exception)
   * when some objects remains locked.
   */
  void unlockAll() {
    bnh.unlockAll();
    ech.unlockAll();
  }
}

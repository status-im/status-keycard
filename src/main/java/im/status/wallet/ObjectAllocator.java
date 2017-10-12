package im.status.wallet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * The control point for unified allocation of arrays and objects with customable
 * specification of allocator type (RAM/EEPROM) for particular array. Allows for 
 * quick personalization and optimization of memory use when compiling for cards 
 * with more/less available memory. 
 *
 * @author Petr Svenda
 */
public class ObjectAllocator {
  short allocatedInRAM = 0;
  short allocatedInEEPROM = 0;
  byte[] ALLOCATOR_TYPE_ARRAY = null;

  public static final byte BNH_helper_BN_array1    = 0;
  public static final byte BNH_helper_BN_array2    = 1;
  public static final byte BNH_helper_BN_A         = 2;
  public static final byte BNH_helper_BN_B         = 3;
  public static final byte BNH_helper_BN_C         = 4;
  public static final byte BNH_helper_BN_D         = 5;
  public static final byte BNH_helper_BN_E         = 6;
  public static final byte BNH_helper_BN_F         = 7;

  public static final byte ECPH_helperEC_BN_A      = 8;
  public static final byte ECPH_helperEC_BN_B      = 9;
  public static final byte ECPH_helperEC_BN_C      = 10;
  public static final byte ECPH_helperEC_BN_D      = 11;
  public static final byte ECPH_helperEC_BN_E      = 12;
  public static final byte ECPH_helperEC_BN_F      = 13;
  public static final byte ECPH_uncompressed_point_arr1 = 14;
  public static final byte ECPH_hashArray          = 15;

  public static final short ALLOCATOR_TYPE_ARRAY_LENGTH = (short) (ECPH_hashArray + 1);

  /**
   * Creates new allocator control object, resets performance counters
   */
  public ObjectAllocator() {
    ALLOCATOR_TYPE_ARRAY = new byte[ALLOCATOR_TYPE_ARRAY_LENGTH];
    setAllAllocatorsRAM();
    resetAllocatorCounters();
  }
  /**
   * All type of allocator for all object as EEPROM
   */
  public final void setAllAllocatorsEEPROM() {
    Util.arrayFillNonAtomic(ALLOCATOR_TYPE_ARRAY, (short) 0, (short) ALLOCATOR_TYPE_ARRAY.length, JCSystem.MEMORY_TYPE_PERSISTENT);
  }
  /**
   * All type of allocator for all object as RAM
   */
  public void setAllAllocatorsRAM() {
    Util.arrayFillNonAtomic(ALLOCATOR_TYPE_ARRAY, (short) 0, (short) ALLOCATOR_TYPE_ARRAY.length, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
  }
  /**
   * All type of allocator for selected object as RAM (faster), rest EEPROM (saving RAM)
   * The current settings is heuristically obtained from measurements of performance of Bignat and ECPoint operations
   */
  public void setAllocatorsTradeoff() {
    // Set initial allocators into EEPROM
    setAllAllocatorsEEPROM();

    // Put only the most perfromance relevant ones into RAM
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_array1] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_array2] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_D] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_E] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_F] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[ECPH_helperEC_BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[ECPH_helperEC_BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    ALLOCATOR_TYPE_ARRAY[ECPH_uncompressed_point_arr1] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
  }

  /**
   * Allocates new byte[] array with provided length either in RAM or EEPROM based on an allocator type.
   * Method updates internal counters of bytes allocated with specific allocator. Use {@code getAllocatedInRAM()}
   * or {@code getAllocatedInEEPROM} for counters readout.
   * @param length    length of array
   * @param allocatorType type of allocator
   * @return allocated array
   */
  public byte[] allocateByteArray(short length, byte allocatorType) {
    switch (allocatorType) {
      case JCSystem.MEMORY_TYPE_PERSISTENT:
        allocatedInEEPROM += length;
        return new byte[length];
      case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
        allocatedInRAM += length;
        return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_RESET);
      case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
        allocatedInRAM += length;
        return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
    }
    return null;
  }

  /**
   * Returns pre-set allocator type for provided object identified by unique objectAllocatorID
   * @param objectAllocatorID unique id of target object
   * @return allocator type
   */
  public byte getAllocatorType(short objectAllocatorID) {
    if (objectAllocatorID >= 0 && objectAllocatorID <= (short) ALLOCATOR_TYPE_ARRAY.length) {
      return ALLOCATOR_TYPE_ARRAY[objectAllocatorID];
    } else {
      ISOException.throwIt(ReturnCodes.SW_ALLOCATOR_INVALIDOBJID);
      return -1;
    }
  }

  /**
   * Returns number of bytes allocated in RAM via {@code allocateByteArray()} since last reset of counters.
   * @return number of bytes allocated in RAM via this control object
   */
  public short getAllocatedInRAM() {
    return allocatedInRAM;
  }
  /**
   * Returns number of bytes allocated in EEPROM via {@code allocateByteArray()}
   * since last reset of counters.
   *
   * @return number of bytes allocated in EEPROM via this control object
   */
  public short getAllocatedInEEPROM() {
    return allocatedInEEPROM;
  }
  /**
   * Resets counters of allocated bytes in RAM and EEPROM
   */
  public final void resetAllocatorCounters() {
    allocatedInRAM = 0;
    allocatedInEEPROM = 0;
  }
}

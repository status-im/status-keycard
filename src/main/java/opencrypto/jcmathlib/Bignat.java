/**
 * Credits: Based on Bignat library from OV-chip project https://ovchip.cs.ru.nl/OV-chip_2.0 by Radboud University Nijmegen 
 */
package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.crypto.Cipher;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class Bignat {
  private final ECConfig ecc;
  /**
   * Configuration flag controlling re-allocation of internal array. If true, internal Bignat buffer can be enlarged during clone
   * operation if required (keep false to prevent slow reallocations)
   */
  boolean ALLOW_RUNTIME_REALLOCATION = false;

  /**
   * Configuration flag controlling clearing of shared Bignats on lock as prevention of unwanted leak of sensitive information from previous operation.
   * If true, internal storage array is erased once Bignat is locked for use
   */
  boolean ERASE_ON_LOCK = false;
  /**
   * Configuration flag controlling clearing of shared Bignats on unlock as
   * prevention of unwanted leak of sensitive information to next operation.
   * If true, internal storage array is erased once Bignat is unlocked from use
   */
  boolean ERASE_ON_UNLOCK = false;

  /**
   * Factor for converting digit size into short length. 1 for the short/short
   * converting, 4 for the int/long configuration.
   *
   */
  public static final short size_multiplier = 1;

  /**
   * Bitmask for extracting a digit out of a longer int/short value. short
   * 0xff for the short/short configuration, long 0xffffffffL the int/long
   * configuration.
   */
  public static final short digit_mask = 0xff;

  /**
   * Bitmask for the highest bit in a digit. short 0x80 for the short/short
   * configuration, long 0x80000000 for the int/long configuration.
   *
   */
  public static final short digit_first_bit_mask = 0x80;

  /**
   * Bitmask for the second highest bit in a digit. short 0x40 for the
   * short/short configuration, long 0x40000000 for the int/long
   * configuration.
   *
   */
  public static final short digit_second_bit_mask = 0x40;

  /**
   * Bitmask for the two highest bits in a digit. short 0xC0 for the
   * short/short configuration, long 0xC0000000 for the int/long
   * configuration.
   *
   */
  public static final short digit_first_two_bit_mask = 0xC0;

  /**
   * Size in bits of one digit. 8 for the short/short configuration, 32 for
   * the int/long configuration.
   */
  public static final short digit_len = 8;

  /**
   * Size in bits of a double digit. 16 for the short/short configuration, 64
   * for the int/long configuration.
   */
  private static final short double_digit_len = 16;

  /**
   * Bitmask for erasing the sign bit in a double digit. short 0x7fff for the
   * short/short configuration, long 0x7fffffffffffffffL for the int/long
   * configuration.
   */
  private static final short positive_double_digit_mask = 0x7fff;

  /**
   * Bitmask for the highest bit in a double digit.
   */
  public static final short highest_digit_bit = (short) (1L << (digit_len - 1));

  /**
   * The base as a double digit. The base is first value that does not fit
   * into a single digit. 2^8 for the short/short configuration and 2^32 for
   * the int/long configuration.
   */
  public static final short bignat_base = (short) (1L << digit_len);

  /**
   * Bitmask with just the highest bit in a double digit.
   */
  public static final short highest_double_digit_bit = (short) (1L << (double_digit_len - 1));

  /**
   * Digit array. Elements have type byte.
   */

  /**
   * Internal storage array for this Bignat. The current version uses byte array with
   * intermediate values stored which can be quickly processed with
   */
  private byte[] value;
  private short size = -1;     // Current size of stored Bignat. Current number is encoded in first {@code size} of value array, starting from value[0]
  private short max_size = -1; // Maximum size of this Bignat. Corresponds to value.length
  private byte allocatorType = JCSystem.MEMORY_TYPE_PERSISTENT; // Memory storage type for value buffer

  private boolean bLocked = false;    // Logical flag to store info if this Bignat is currently used for some operation. Used as a prevention of unintentional parallel use of same temporary pre-allocated Bignats.

  /**
   * Construct a Bignat of size {@code size} in shorts. Allocated in EEPROM or RAM based on
   * {@code allocatorType}. JCSystem.MEMORY_TYPE_PERSISTENT, in RAM otherwise.
   *
   * @param size the size of the new Bignat in bytes
   * @param allocatorType type of allocator storage
   *      JCSystem.MEMORY_TYPE_PERSISTENT => EEPROM (slower writes, but RAM is saved)
   *      JCSystem.MEMORY_TYPE_TRANSIENT_RESET => RAM
   *      JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT => RAM
   * @param ecc {@code ECConfig} class with all relevant settings and helper
   *      objects
   */
  public Bignat(short size, byte allocatorType, ECConfig ecc) {
    this.ecc = ecc;
    allocate_storage_array(size, allocatorType);
  }

  /**
   * Construct a Bignat with provided array used as internal storage as well as initial value.
   * No copy of array is made. If this Bignat is used in operation which modifies the Bignat value,
   * content of provided array is changed.
   * @param valueBuffer internal storage
   * @param ecc {@code ECConfig} class with all relevant settings and helper objects
   */
  public Bignat(byte[] valueBuffer, ECConfig ecc) {
    this.ecc = ecc;
    this.size = (short) valueBuffer.length;
    this.max_size = (short) valueBuffer.length;
    this.allocatorType = -1; // no allocator
    this.value = valueBuffer;
  }

  /**
   * Lock/reserve this bignat for subsequent use.
   * Used to protect corruption of pre-allocated temporary Bignats used in different,
   * potentially nested operations. Must be unlocked by {@code unlock()} later on.
   */
  public void lock() {
    if (!bLocked) {
      bLocked = true;
      if (ERASE_ON_LOCK) {
        erase();
      }
    }
    else {
      // this Bignat is already locked, raise exception (incorrect sequence of locking and unlocking)
      ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
    }
  }
  /**
   * Unlock/release this bignat from use. Used to protect corruption
   * of pre-allocated temporary Bignats used in different nested operations.
   * Must be locked before.
   *
   */
  public void unlock() {
    if (bLocked) {
      bLocked = false;
      if (ERASE_ON_UNLOCK) {
        erase();
      }
    } else {
      // this Bignat is not locked, raise exception (incorrect sequence of locking and unlocking)
      ISOException.throwIt(ReturnCodes.SW_LOCK_NOTLOCKED);
    }
  }

  /**
   * Return current state of logical lock of this object
   * @return true if object is logically locked (reserved), false otherwise
   */
  public boolean isLocked() {
    return bLocked;
  }

  /**
   * Return this Bignat as byte array. For the short/short configuration
   * simply the digit array is returned. For other configurations a new short
   * array is allocated and returned. Modifying the returned short array
   * therefore might or might not change this bignat.
   * IMPORTANT: this function returns directly the underlying storage array.
   * Current value of this Bignat can be stored in smaller number of bytes.
   * Use {@code getLength()} method to obtain actual size.
   *
   * @return this bignat as byte array
   */
  public byte[] as_byte_array() {
    return value;
  }

  /**
   * Serialize this Bignat value into a provided buffer
   * @param buffer target buffer
   * @param bufferOffset start offset in buffer
   * @return number of bytes copied
   */
  public short copy_to_buffer(byte[] buffer, short bufferOffset) {
    Util.arrayCopyNonAtomic(value, (short) 0, buffer, bufferOffset, size);
    return size;
  }


  /**
   * Return the size in digits. Provides access to the internal {@link #size}
   * field.
   * <P>
   * The return value is adjusted by {@link #set_size}.
   *
   * @return size in digits.
   */
  public short length() {
    return size;
  }

  /**
   * Sets internal size of Bignat. Previous value are kept so value is either non-destructively trimmed or enlarged.
   * @param newSize new size of Bignat. Must be in range of [0, max_size] where max_size was provided during object creation
   */
  public void set_size(short newSize) {
    if (newSize < 0 || newSize > max_size) {
      ISOException.throwIt(ReturnCodes.SW_BIGNAT_RESIZETOLONGER);
    }
    else {
      this.size = newSize;
    }
  }

  /**
   * Resize internal length of this Bignat to maximum size given during object
   * creation. If required, object is also zeroized
   *
   * @param bZeroize if true, all bytes of internal array are also set to
   * zero. If false, previous value is kept.
   */
  public void resize_to_max(boolean bZeroize) {
    set_size(max_size);
    if (bZeroize) {
      zero();
    }
  }

  /**
   * Create Bignat with different number of bytes used. Will cause longer number
   * to shrink (loss of the more significant bytes) and shorter to be prepended with zeroes
   *
   * @param new_size new size in bytes
   */
  void deep_resize(short new_size) {
    if (new_size > this.max_size) {
      if (ALLOW_RUNTIME_REALLOCATION) {
        allocate_storage_array(new_size, this.allocatorType);
      } else {
        ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED); // Reallocation to longer size not permitted
      }
    }

    if (new_size == this.size) {
      // No need to resize enything, same length
    }
    else {
      short this_start, other_start, len;
      if (this.size >= new_size) {
        this_start = (short) (this.size - new_size);
        other_start = 0;
        len = new_size;

        // Shrinking/cropping
        Util.arrayCopyNonAtomic(value, this_start, ecc.bnh.fnc_deep_resize_tmp, (short) 0, len);
        Util.arrayCopyNonAtomic(ecc.bnh.fnc_deep_resize_tmp, (short) 0, value, (short) 0, len); // Move bytes in item array towards beggining
        // Erase rest of allocated array with zeroes (just as sanitization)
        short toErase = (short) (this.max_size - new_size);
        if (toErase > 0) {
          Util.arrayFillNonAtomic(value, new_size, toErase, (byte) 0);
        }
      } else {
        this_start = 0;
        other_start = (short) (new_size - this.size);
        len = this.size;
        // Enlarging => Insert zeroes at begging, move bytes in item array towards the end
        Util.arrayCopyNonAtomic(value, this_start, ecc.bnh.fnc_deep_resize_tmp, (short) 0, len);
        // Move bytes in item array towards end
        Util.arrayCopyNonAtomic(ecc.bnh.fnc_deep_resize_tmp, (short) 0, value, other_start, len);
        // Fill begin of array with zeroes (just as sanitization)
        if (other_start > 0) {
          Util.arrayFillNonAtomic(value, (short) 0, other_start, (byte) 0);
        }
      }

      set_size(new_size);
    }
  }


  /**
   * Appends zeros in the suffix to reach the defined byte length
   * Essentially multiplies the number with 16 (HEX)
   * @param targetLength required length including appended zeroes
   * @param outBuffer output buffer for value with appended zeroes
   * @param outOffset start offset inside outBuffer for write
   */
  public void append_zeros(short targetLength, byte[] outBuffer, short outOffset) {
    Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, outOffset, this.size); //copy the value
    Util.arrayFillNonAtomic(outBuffer, (short) (outOffset + this.size), (short) (targetLength - this.size), (byte) 0); //append zeros
  }
  /**
   * Prepends zeros before the value of this Bignat up to target length.
   *
   * @param targetLength required length including prepended zeroes
   * @param outBuffer output buffer for value with prepended zeroes
   * @param outOffset start offset inside outBuffer for write
   */
  public void prepend_zeros(short targetLength, byte[] outBuffer, short outOffset) {
    short other_start = (short) (targetLength - this.size);
    if (other_start > 0) {
      Util.arrayFillNonAtomic(outBuffer, outOffset, other_start, (byte) 0); //fill prefix with zeros
    }
    Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, (short) (outOffset + other_start), this.size); //copy the value
  }

  /**
   * Remove leading zeroes (if any) from Bignat value and decrease size accordingly
   */
  public void shrink() {
    short i = 0;
    for (i = 0; i < this.length(); i++) { // Find first non-zero byte
      if (this.value[i] != 0) {
        break;
      }
    }

    short new_size = (short)(this.size-i);
    if (new_size < 0) {
      ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDRESIZE);
    }
    this.deep_resize(new_size);
  }


  /**
   * Stores zero in this object for currently used subpart given by internal size.
   */
  public void zero() {
    Util.arrayFillNonAtomic(value, (short) 0, this.size, (byte) 0);
  }
  /**
   * Stores zero in this object for whole internal buffer regardless of current size.
   */
  public void zero_complete() {
    Util.arrayFillNonAtomic(value, (short) 0, (short) value.length, (byte) 0);
  }

  /**
   * Erase value stored inside this Bignat
   */
  public void erase() {
    zero_complete();
  }


  /**
   * Stores one in this object. Keeps previous size of this Bignat
   * (1 is prepended with required number of zeroes).
   */
  public void one() {
    this.zero();
    value[(short) (size - 1)] = 1;
  }
  /**
   * Stores two in this object. Keeps previous size of this Bignat (2 is
   * prepended with required number of zeroes).
   */
  public void two() {
    this.zero();
    value[(short) (size - 1)] = 0x02;
  }

  public void three() {
    this.zero();
    value[(short) (size - 1)] = 0x03;
  }

  public void four() {
    this.zero();
    value[(short) (size - 1)] = 0x04;
  }

  public void five() {
    this.zero();
    value[(short) (size - 1)] = 0x05;
  }
  public void eight() {
    this.zero();
    value[(short) (size - 1)] = 0x08;
  }

  public void ten() {
    this.zero();
    value[(short) (size - 1)] = 0x0A;
  }

  public void twentyfive() {
    this.zero();
    value[(short)(size-1)] = 0x19;
  }

  public void twentyseven() {
    this.zero();
    value[(short)(size-1)] = 0x1B;
  }

  public void athousand() {
    this.zero();
    value[(short)(size-2)] = (byte)0x03;
    value[(short)(size-1)] = (byte)0xE8;
  }




  /**
   * Copies {@code other} into this. No size requirements. If {@code other}
   * has more digits then the superfluous leading digits of {@code other} are
   * asserted to be zero. If this bignat has more digits than its leading
   * digits are correctly initilized to zero. This function will not change size
   * attribute of this object.
   *
   * @param other
   *            Bignat to copy into this object.
   */
  public void copy(Bignat other) {
    short this_start, other_start, len;
    if (this.size >= other.size) {
      this_start = (short) (this.size - other.size);
      other_start = 0;
      len = other.size;
    } else {
      this_start = 0;
      other_start = (short) (other.size - this.size);
      len = this.size;
      // Verify here that other have leading zeroes up to other_start
      for (short i = 0; i < other_start; i ++) {
        if (other.value[i] != 0) {
          ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDCOPYOTHER);
        }
      }
    }

    if (this_start > 0) {
      // if this bignat has more digits than its leading digits are initilized to zero
      Util.arrayFillNonAtomic(this.value, (short) 0, this_start, (byte) 0);
    }
    Util.arrayCopyNonAtomic(other.value, other_start, this.value, this_start, len);
  }

  /**
   * Copies content of {@code other} into this and set size of this to {@code other}.
   * The size attribute (returned by length()) is updated. If {@code other}
   * is longer than maximum capacity of this, internal buffer is reallocated if enabled
   * (ALLOW_RUNTIME_REALLOCATION), otherwise exception is thrown.
   * @param other
   *            Bignat to clone into this object.
   */
  public void clone(Bignat other) {
    // Reallocate array only if current array cannot store the other value and reallocation is enabled by ALLOW_RUNTIME_REALLOCATION
    if (this.max_size < other.length()) {
      // Reallocation necessary
      if (ALLOW_RUNTIME_REALLOCATION) {
        allocate_storage_array(other.length(), this.allocatorType);
      }
      else {
        ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED);
      }
    }

    // copy value from other into proper place in this (this can be longer than other so rest of bytes wil be filled with 0)
    other.copy_to_buffer(this.value, (short) 0);
    if (this.max_size > other.length()) {
      Util.arrayFillNonAtomic(this.value, other.length(), (short) (this.max_size - other.length()), (byte) 0);
    }
    this.size = other.length();
  }

  /**
   * Equality check. Requires that this object and other have the same size or are padded with zeroes.
   * Returns true if all digits (except for leading zeroes) are equal.
   *
   *
   * @param other Bignat to compare
   * @return true if this and other have the same value, false otherwise.
   */
  public boolean same_value(Bignat other) {
    short hashLen;
    // Compare using hash engine
    // The comparison is made with hash of point values instead of directly values.
    // This way, offset of first mismatching byte is not leaked via timing side-channel.
    if (this.length() == other.length()) {
      // Same length, we can hash directly from BN values
      ecc.bnh.hashEngine.doFinal(this.value, (short) 0, this.length(), ecc.bnh.fnc_same_value_hash, (short) 0);
      hashLen = ecc.bnh.hashEngine.doFinal(other.value, (short) 0, other.length(), ecc.bnh.fnc_same_value_array1, (short) 0);
    }
    else {
      // Different length of bignats - can be still same if prepended with zeroes
      // Find the length of longer one and padd other one with starting zeroes
      if (this.length() < other.length()) {
        this.prepend_zeros(other.length(), ecc.bnh.fnc_same_value_array1, (short) 0);
        ecc.bnh.hashEngine.doFinal(ecc.bnh.fnc_same_value_array1, (short) 0, other.length(), ecc.bnh.fnc_same_value_hash, (short) 0);
        hashLen = ecc.bnh.hashEngine.doFinal(other.value, (short) 0, other.length(), ecc.bnh.fnc_same_value_array1, (short) 0);
      }
      else {
        other.prepend_zeros(this.length(), ecc.bnh.fnc_same_value_array1, (short) 0);
        ecc.bnh.hashEngine.doFinal(ecc.bnh.fnc_same_value_array1, (short) 0, this.length(), ecc.bnh.fnc_same_value_hash, (short) 0);
        hashLen = ecc.bnh.hashEngine.doFinal(this.value, (short) 0, this.length(), ecc.bnh.fnc_same_value_array1, (short) 0);
      }
    }

    boolean bResult = Util.arrayCompare(ecc.bnh.fnc_same_value_hash, (short) 0, ecc.bnh.fnc_same_value_array1, (short) 0, hashLen) == 0;

    return bResult;
  }


  /**
   * Addition of big integers x and y stored in byte arrays with specified offset and length.
   * The result is stored into x array argument.
   * @param x          array with first bignat
   * @param xOffset    start offset in array of {@code x}
   * @param xLength    length of {@code x}
   * @param y          array with second bignat
   * @param yOffset    start offset in array of {@code y}
   * @param yLength    length of {@code y}
   * @return true if carry of most significant byte occurs, false otherwise
   */
  public static boolean add(byte[] x, short xOffset, short xLength, byte[] y,
                            short yOffset, short yLength) {
    short result = 0;
    short i = (short) (xLength + xOffset - 1);
    short j = (short) (yLength + yOffset - 1);

    for (; i >= xOffset && j >= 0; i--, j--) {
      result = (short) (result + (short) (x[i] & digit_mask) + (short) (y[j] & digit_mask));

      x[i] = (byte) (result & digit_mask);
      result = (short) ((result >> digit_len) & digit_mask);
    }
    while (result > 0 && i >= xOffset) {
      result = (short) (result + (short) (x[i] & digit_mask));
      x[i] = (byte) (result & digit_mask);
      result = (short) ((result >> digit_len) & digit_mask);
      i--;
    }

    return result != 0;
  }

  /**
   * Subtracts big integer y from x specified by offset and length.
   * The result is stored into x array argument.
   * @param x array with first bignat
   * @param xOffset start offset in array of {@code x}
   * @param xLength length of {@code x}
   * @param y array with second bignat
   * @param yOffset start offset in array of {@code y}
   * @param yLength length of {@code y}
   * @return true if carry of most significant byte occurs, false otherwise
   */
  public static boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
                                 short yOffset, short yLength) {
    short i = (short) (xLength + xOffset - 1);
    short j = (short) (yLength + yOffset - 1);
    short carry = 0;
    short subtraction_result = 0;

    for (; i >= xOffset && j >= yOffset; i--, j--) {
      subtraction_result = (short) ((x[i] & digit_mask) - (y[j] & digit_mask) - carry);
      x[i] = (byte) (subtraction_result & digit_mask);
      carry = (short) (subtraction_result < 0 ? 1 : 0);
    }
    for (; i >= xOffset && carry > 0; i--) {
      if (x[i] != 0) {
        carry = 0;
      }
      x[i] -= 1;
    }

    return carry > 0;
  }

  /**
   * Substract provided other bignat from this bignat.
   * @param other bignat to be substracted from this
   */
  public void subtract(Bignat other) {
    this.times_minus(other, (short) 0, (short) 1);
  }

  /**
   * Scaled subtraction. Subtracts {@code mult * 2^(}{@link #digit_len}
   * {@code  * shift) * other} from this.
   * <P>
   * That is, shifts {@code mult * other} precisely {@code shift} digits to
   * the left and subtracts that value from this. {@code mult} must be less
   * than {@link #bignat_base}, that is, it must fit into one digit. It is
   * only declared as short here to avoid negative values.
   * <P>
   * {@code mult} has type short.
   * <P>
   * No size constraint. However, an assertion is thrown, if the result would
   * be negative. {@code other} can have more digits than this object, but
   * then sufficiently many leading digits must be zero to avoid the
   * underflow.
   * <P>
   * Used in division.
   *
   * @param other
   *            Bignat to subtract from this object
   * @param shift
   *            number of digits to shift {@code other} to the left
   * @param mult
   *            of type short, multiple of {@code other} to subtract from this
   *            object. Must be below {@link #bignat_base}.
   */
  public void times_minus(Bignat other, short shift, short mult) {
    short akku = 0;
    short subtraction_result;
    short i = (short) (this.size - 1 - shift);
    short j = (short) (other.size - 1);
    for (; i >= 0 && j >= 0; i--, j--) {
      akku = (short) (akku + (short) (mult * (other.value[j] & digit_mask)));
      subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));

      value[i] = (byte) (subtraction_result & digit_mask);
      akku = (short) ((akku >> digit_len) & digit_mask);
      if (subtraction_result < 0) {
        akku++;
      }
    }

    // deal with carry as long as there are digits left in this
    while (i >= 0 && akku != 0) {
      subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));
      value[i] = (byte) (subtraction_result & digit_mask);
      akku = (short) ((akku >> digit_len) & digit_mask);
      if (subtraction_result < 0) {
        akku++;
      }
      i--;
    }
  }

  /**
   * Quick function for decrement of this bignat value by 1. Faster than {@code substract(Bignat.one())}
   */
  public void decrement_one() {
    short tmp = 0;
    for (short i = (short) (this.size - 1); i >= 0; i--) {
      tmp = (short) (this.value[i] & 0xff);
      this.value[i] = (byte) (tmp - 1);
      if (tmp != 0) {
        break; // CTO
      }
      else {
        // need to modify also one byte up, continue with cycle
      }
    }
  }
  /**
   * Quick function for increment of this bignat value by 1. Faster than
   * {@code add(Bignat.one())}
   */
  public void increment_one() {
    short tmp = 0;
    for (short i = (short) (this.size - 1); i >= 0; i--) {
      tmp = (short) (this.value[i] & 0xff);
      this.value[i] = (byte) (tmp + 1);
      if (tmp < 255) {
        break; // CTO
      } else {
        // need to modify also one byte up (carry) , continue with cycle
      }
    }
  }

  /**
   * Index of the most significant 1 bit.
   * <P>
   * {@code x} has type short.
   * <P>
   * Utility method, used in division.
   *
   * @param x
   *            of type short
   * @return index of the most significant 1 bit in {@code x}, returns
   *         {@link #double_digit_len} for {@code x == 0}.
   */
  private static short highest_bit(short x) {
    for (short i = 0; i < double_digit_len; i++) {
      if (x < 0) {
        return i;
      }
      x <<= 1;
    }
    return double_digit_len;
  }

  /**
   * Shift to the left and fill. Takes {@code high} {@code middle} {@code low}
   * as 4 digits, shifts them {@code shift} bits to the left and returns the
   * most significant {@link #double_digit_len} bits.
   * <P>
   * Utility method, used in division.
   *
   *
   * @param high
   *            of type short, most significant {@link #double_digit_len} bits
   * @param middle
   *            of type byte, middle {@link #digit_len} bits
   * @param low
   *            of type byte, least significant {@link #digit_len} bits
   * @param shift
   *            amount of left shift
   * @return most significant {@link #double_digit_len} as short
   */
  private static short shift_bits(short high, byte middle, byte low,
                                  short shift) {
    // shift high
    high <<= shift;

    // merge middle bits
    byte mask = (byte) (digit_mask << (shift >= digit_len ? 0 : digit_len
        - shift));
    short bits = (short) ((short) (middle & mask) & digit_mask);
    if (shift > digit_len) {
      bits <<= shift - digit_len;
    }
    else {
      bits >>>= digit_len - shift;
    }
    high |= bits;

    if (shift <= digit_len) {
      return high;
    }

    // merge low bits
    mask = (byte) (digit_mask << double_digit_len - shift);
    bits = (short) ((((short) (low & mask) & digit_mask) >> double_digit_len - shift));
    high |= bits;

    return high;
  }

  /**
   * Scaled comparison. Compares this number with {@code other * 2^(}
   * {@link #digit_len} {@code * shift)}. That is, shifts {@code other}
   * {@code shift} digits to the left and compares then. This bignat and
   * {@code other} will not be modified inside this method.
   * <P>
   *
   * As optimization {@code start} can be greater than zero to skip the first
   * {@code start} digits in the comparison. These first digits must be zero
   * then, otherwise an assertion is thrown. (So the optimization takes only
   * effect when <a
   * href="../../../overview-summary.html#NO_CARD_ASSERT">NO_CARD_ASSERT</a>
   * is defined.)
   *
   * @param other
   *            Bignat to compare to
   * @param shift
   *            left shift of other before the comparison
   * @param start
   *            digits to skip at the beginning
   * @return true if this number is strictly less than the shifted
   *         {@code other}, false otherwise.
   */
  public boolean shift_lesser(Bignat other, short shift, short start) {
    short j;

    j = (short) (other.size + shift - this.size + start);
    short this_short, other_short;
    for (short i = start; i < this.size; i++, j++) {
      this_short = (short) (this.value[i] & digit_mask);
      if (j >= 0 && j < other.size) {
        other_short = (short) (other.value[j] & digit_mask);
      }
      else {
        other_short = 0;
      }
      if (this_short < other_short) {
        return true; // CTO
      }
      if (this_short > other_short) {
        return false;
      }
    }
    return false;
  }

  /**
   * Compares this and other bignat.
   * @param other other value to compare with
   * @return true if this bignat is smaller, false if bigger or equal
   */
  public boolean smaller(Bignat other) {
    short index_this = 0;
    for (short i = 0; i < this.length(); i++) {
      if (this.value[i] != 0x00) {
        index_this = i;
      }
    }

    short index_other = 0;
    for (short i = 0; i < other.length(); i++) {
      if (other.value[i] != 0x00) {
        index_other = i;
      }
    }

    if ((short) (this.length() - index_this) < (short) (other.length() - index_other)) {
      return true; // CTO
    }
    short i = 0;
    while (i < this.length() && i < other.length()) {
      if (((short) (this.value[i] & digit_mask)) < ((short) (other.value[i] & digit_mask))) {
        return true; // CTO
      }
      i = (short) (1 + i);
    }

    return false;
  }


  /**
   * Comparison of this and other.
   *
   * @param other
   *            Bignat to compare with
   * @return true if this number is strictly lesser than {@code other}, false
   *         otherwise.
   */
  public boolean lesser(Bignat other) {
    return this.shift_lesser(other, (short) 0, (short) 0);
  }

  /**
   * Test equality with zero.
   *
   * @return true if this bignat equals zero.
   */
  public boolean is_zero() {
    for (short i = 0; i < size; i++) {
      if (value[i] != 0) {
        return false; // CTO
      }
    }
    return true;
  }

  /** Check if stored bignat is odd.
   *
   * @return  true if odd, false if even
   */
  public boolean is_odd() {
    if ((value[(short) (this.size - 1)] & 1) == 0) {
      return false; // CTO
    }
    return true;
  }

  /**
   * Remainder and Quotient. Divide this number by {@code divisor} and store
   * the remainder in this. If {@code quotient} is non-null store the quotient
   * there.
   * <P>
   * There are no direct size constraints, but if {@code quotient} is
   * non-null, it must be big enough for the quotient, otherwise an assertion
   * is thrown.
   * <P>
   * Uses schoolbook division inside and has O^2 complexity in the difference
   * of significant digits of the divident (in this number) and the divisor.
   * For numbers of equal size complexity is linear.
   *
   * @param divisor
   *            must be non-zero
   * @param quotient
   *            gets the quotient if non-null
   */
  public void remainder_divide(Bignat divisor, Bignat quotient) {
    // There are some size requirements, namely that quotient must
    // be big enough. However, this depends on the value of the
    // divisor and is therefore not stated here.

    // zero-initialize the quotient, because we are only adding to it below
    if (quotient != null) {
      quotient.zero();
    }

    // divisor_index is the first nonzero digit (short) in the divisor
    short divisor_index = 0;
    while (divisor.value[divisor_index] == 0) {
      divisor_index++;
    }

    // The size of this might be different from divisor. Therefore,
    // for the first subtraction round we have to shift the divisor
    // divisor_shift = this.size - divisor.size + divisor_index
    // digits to the left. If this amount is negative, then
    // this is already smaller then divisor and we are done.
    // Below we do divisor_shift + 1 subtraction rounds. As an
    // additional loop index we also count the rounds (from
    // zero upwards) in division_round. This gives access to the
    // first remaining divident digits.
    short divisor_shift = (short) (this.size - divisor.size + divisor_index);
    short division_round = 0;

    // We could express now a size constraint, namely that
    // divisor_shift + 1 <= quotient.size
    // However, in the proof protocol we divide x / v, where
    // x has 2*n digits when v has n digits. There the above size
    // constraint is violated, the division is however valid, because
    // it will always hold that x < v * (v - 1) and therefore the
    // quotient will always fit into n digits.
    // System.out.format("XX this size %d div ind %d div shift %d " +
    // "quo size %d\n" +
    // "%s / %s\n",
    // this.size,
    // divisor_index,
    // divisor_shift,
    // quotient != null ? quotient.size : -1,
    // this.to_hex_string(),
    // divisor.to_hex_string());
    // The first digits of the divisor are needed in every
    // subtraction round.
    short first_divisor_digit = (short) (divisor.value[divisor_index] & digit_mask);
    short divisor_bit_shift = (short) (highest_bit((short) (first_divisor_digit + 1)) - 1);
    byte second_divisor_digit = divisor_index < (short) (divisor.size - 1) ? divisor.value[(short) (divisor_index + 1)]
        : 0;
    byte third_divisor_digit = divisor_index < (short) (divisor.size - 2) ? divisor.value[(short) (divisor_index + 2)]
        : 0;

    // The following variables are used inside the loop only.
    // Declared here as optimization.
    // divident_digits and divisor_digit hold the first one or two
    // digits. Needed to compute the multiple of the divisor to
    // subtract from this.
    short divident_digits, divisor_digit;

    // To increase precisision the first digits are shifted to the
    // left or right a bit. The following variables compute the shift.
    short divident_bit_shift, bit_shift;

    // Declaration of the multiple, with which the divident is
    // multiplied in each round and the quotient_digit. Both are
    // a single digit, but declared as a double digit to avoid the
    // trouble with negative numbers. If quotient != null multiple is
    // added to the quotient. This addition is done with quotient_digit.
    short multiple, quotient_digit;
    short numLoops = 0;
    short numLoops2 = 0;
    while (divisor_shift >= 0) {
      numLoops++; // CTO number of outer loops is constant (for given length of divisor)
      // Keep subtracting from this until
      // divisor * 2^(8 * divisor_shift) is bigger than this.
      while (!shift_lesser(divisor, divisor_shift,
          (short) (division_round > 0 ? division_round - 1 : 0))) {
        numLoops2++; // BUGBUG: CTO - number of these loops fluctuates heavily => strong impact on operation time
        // this is bigger or equal than the shifted divisor.
        // Need to subtract some multiple of divisor from this.
        // Make a conservative estimation of the multiple to subtract.
        // We estimate a lower bound to avoid underflow, and continue
        // to subtract until the remainder in this gets smaller than
        // the shifted divisor.
        // For the estimation get first the two relevant digits
        // from this and the first relevant digit from divisor.
        divident_digits = division_round == 0 ? 0
            : (short) ((short) (value[(short) (division_round - 1)]) << digit_len);
        divident_digits |= (short) (value[division_round] & digit_mask);

        // The multiple to subtract from this is
        // divident_digits / divisor_digit, but there are two
        // complications:
        // 1. divident_digits might be negative,
        // 2. both might be very small, in which case the estimated
        // multiple is very inaccurate.
        if (divident_digits < 0) {
          // case 1: shift both one bit to the right
          // In standard java (ie. in the test frame) the operation
          // for >>= and >>>= seems to be done in integers,
          // even if the left hand side is a short. Therefore,
          // for a short left hand side there is no difference
          // between >>= and >>>= !!!
          // Do it the complicated way then.
          divident_digits = (short) ((divident_digits >>> 1) & positive_double_digit_mask);
          divisor_digit = (short) ((first_divisor_digit >>> 1) & positive_double_digit_mask);
        } else {
          // To avoid case 2 shift both to the left
          // and add relevant bits.
          divident_bit_shift = (short) (highest_bit(divident_digits) - 1);
          // Below we add one to divisor_digit to avoid underflow.
          // Take therefore the highest bit of divisor_digit + 1
          // to avoid running into the negatives.
          bit_shift = divident_bit_shift <= divisor_bit_shift ? divident_bit_shift
              : divisor_bit_shift;

          divident_digits = shift_bits(
              divident_digits,
              division_round < (short) (this.size - 1) ? value[(short) (division_round + 1)]
                  : 0,
              division_round < (short) (this.size - 2) ? value[(short) (division_round + 2)]
                  : 0, bit_shift);
          divisor_digit = shift_bits(first_divisor_digit,
              second_divisor_digit, third_divisor_digit,
              bit_shift);

        }

        // add one to divisor to avoid underflow
        multiple = (short) (divident_digits / (short) (divisor_digit + 1));

        // Our strategy to avoid underflow might yield multiple == 0.
        // We know however, that divident >= divisor, therefore make
        // sure multiple is at least 1.
        if (multiple < 1) {
          multiple = 1;
        }

        times_minus(divisor, divisor_shift, multiple);

        // build quotient if desired
        if (quotient != null) {
          // Express the size constraint only here. The check is
          // essential only in the first round, because
          // divisor_shift decreases. divisor_shift must be
          // strictly lesser than quotient.size, otherwise
          // quotient is not big enough. Note that the initially
          // computed divisor_shift might be bigger, this
          // is OK, as long as we don't reach this point.

          quotient_digit = (short) ((quotient.value[(short) (quotient.size - 1 - divisor_shift)] & digit_mask) + multiple);
          quotient.value[(short) (quotient.size - 1 - divisor_shift)] = (byte) (quotient_digit);
        }
      }

      // treat loop indices
      division_round++;
      divisor_shift--;
    }
  }


  /**
   * Add short value to this bignat
   * @param other short value to add
   */
  public void add(short other) {
    Util.setShort(ecc.bnh.tmp_array_short, (short) 0, other); // serialize other into array
    this.add_carry(ecc.bnh.tmp_array_short, (short) 0, (short) 2); // add as array
  }

  /**
   * Addition with carry report. Adds other to this number. If this is too
   * small for the result (i.e., an overflow occurs) the method returns true.
   * Further, the result in {@code this} will then be the correct result of an
   * addition modulo the first number that does not fit into {@code this} (
   * {@code 2^(}{@link #digit_len}{@code * }{@link #size this.size}{@code )}),
   * i.e., only one leading 1 bit is missing. If there is no overflow the
   * method will return false.
   * <P>
   *
   * It would be more natural to report the overflow with an
   * {@link javacard.framework.UserException}, however its
   * {@link javacard.framework.UserException#throwIt throwIt} method dies with
   * a null pointer exception when it runs in a host test frame...
   * <P>
   *
   * Asserts that the size of other is not greater than the size of this.
   *
   * @param other
   *            Bignat to add
   * @param otherOffset start offset within other buffer
   * @param otherLen length of other
   * @return true if carry occurs, false otherwise
   */
  public boolean add_carry(byte[] other, short otherOffset, short otherLen) {
    short akku = 0;
    short j = (short) (this.size - 1);
    for (short i = (short) (otherLen - 1); i >= 0 && j >= 0; i--, j--) {
      akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (other[(short) (i + otherOffset)] & digit_mask));

      this.value[j] = (byte) (akku & digit_mask);
      akku = (short) ((akku >> digit_len) & digit_mask);
    }
    // add carry at position j
    while (akku > 0 && j >= 0) {
      akku = (short) (akku + (short) (this.value[j] & digit_mask));
      this.value[j] = (byte) (akku & digit_mask);
      akku = (short) ((akku >> digit_len) & digit_mask);
      j--;
    }

    return akku != 0;
  }
  /**
   * Add with carry. See {@code add_cary()} for full description
   * @param other value to be added
   * @return true if carry happens, false otherwise
   */
  public boolean add_carry(Bignat other) {
    return add_carry(other.value, (short) 0, other.size);
  }


  /**
   * Addition. Adds other to this number.
   * <P>
   * Same as {@link #times_add times_add}{@code (other, 1)} but without the
   * multiplication overhead.
   * <P>
   * Asserts that the size of other is not greater than the size of this.
   *
   * @param other
   *            Bignat to add
   */
  public void add(Bignat other) {
    add_carry(other);
  }

  /**
   * Add other bignat to this bignat modulo {@code modulo} value.
   * @param other value to add
   * @param modulo value of modulo to compute
   */
  public void mod_add(Bignat other, Bignat modulo) {
    short tmp_size = this.size;
    if (tmp_size < other.size) {
      tmp_size = other.size;
    }
    tmp_size++;
    ecc.bnh.fnc_mod_add_tmp.lock();
    ecc.bnh.fnc_mod_add_tmp.set_size(tmp_size);
    ecc.bnh.fnc_mod_add_tmp.zero();
    ecc.bnh.fnc_mod_add_tmp.copy(this);
    ecc.bnh.fnc_mod_add_tmp.add(other);
    ecc.bnh.fnc_mod_add_tmp.mod(modulo);
    ecc.bnh.fnc_mod_add_tmp.shrink();
    this.clone(ecc.bnh.fnc_mod_add_tmp);
    ecc.bnh.fnc_mod_add_tmp.unlock();
  }

  /**
   * Substract other bignat from this bignat modulo {@code modulo} value.
   *
   * @param other value to substract
   * @param modulo value of modulo to apply
   */
  public void mod_sub(Bignat other, Bignat modulo) {
    if (other.lesser(this)) { // CTO
      this.subtract(other);
      this.mod(modulo);
    } else { //other>this (mod-other+this)
      ecc.bnh.fnc_mod_sub_tmpOther.lock();
      ecc.bnh.fnc_mod_sub_tmpOther.clone(other);
      ecc.bnh.fnc_mod_sub_tmpOther.mod(modulo);

      //fnc_mod_sub_tmpThis = new Bignat(this.length());
      ecc.bnh.fnc_mod_sub_tmpThis.lock();
      ecc.bnh.fnc_mod_sub_tmpThis.clone(this);
      ecc.bnh.fnc_mod_sub_tmpThis.mod(modulo);

      ecc.bnh.fnc_mod_sub_tmp.lock();
      ecc.bnh.fnc_mod_sub_tmp.clone(modulo);
      ecc.bnh.fnc_mod_sub_tmp.subtract(ecc.bnh.fnc_mod_sub_tmpOther);
      ecc.bnh.fnc_mod_sub_tmpOther.unlock();
      ecc.bnh.fnc_mod_sub_tmp.add(ecc.bnh.fnc_mod_sub_tmpThis); //this will never overflow as "other" is larger than "this"
      ecc.bnh.fnc_mod_sub_tmpThis.unlock();
      ecc.bnh.fnc_mod_sub_tmp.mod(modulo);
      ecc.bnh.fnc_mod_sub_tmp.shrink();
      this.clone(ecc.bnh.fnc_mod_sub_tmp);
      ecc.bnh.fnc_mod_sub_tmp.unlock();
    }
  }


  /**
   * Scaled addition. Add {@code mult * other} to this number. {@code mult}
   * must be below {@link #bignat_base}, that is, it must fit into one digit.
   * It is only declared as a short here to avoid negative numbers.
   * <P>
   * Asserts (overly restrictive) that this and other have the same size.
   * <P>
   * Same as {@link #times_add_shift times_add_shift}{@code (other, 0, mult)}
   * but without the shift overhead.
   * <P>
   * Used in multiplication.
   *
   * @param other Bignat to add
   * @param mult of short, factor to multiply {@code other} with before
   * addition. Must be less than {@link #bignat_base}.
   */
  public void times_add(Bignat other, short mult) {
    short akku = 0;
    for (short i = (short) (size - 1); i >= 0; i--) {
      akku = (short) (akku + (short) (this.value[i] & digit_mask) + (short) (mult * (other.value[i] & digit_mask)));
      this.value[i] = (byte) (akku & digit_mask);
      akku = (short) ((akku >> digit_len) & digit_mask);
    }
  }

  /**
   * Scaled addition. Adds {@code mult * other * 2^(}{@link #digit_len}
   * {@code * shift)} to this. That is, shifts other {@code shift} digits to
   * the left, multiplies it with {@code mult} and adds then.
   * <P>
   * {@code mult} must be less than {@link #bignat_base}, that is, it must fit
   * into one digit. It is only declared as a short here to avoid negative
   * numbers.
   * <P>
   * Asserts that the size of this is greater than or equal to
   * {@code other.size + shift + 1}.
   *
   * @param x Bignat to add
   * @param mult of short, factor to multiply {@code other} with before
   * addition. Must be less than {@link #bignat_base}.
   * @param shift number of digits to shift {@code other} to the left, before
   * addition.
   */
  public void times_add_shift(Bignat x, short shift, short mult) {
    short akku = 0;
    short j = (short) (this.size - 1 - shift);
    for (short i = (short) (x.size - 1); i >= 0; i--, j--) {
      akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (mult * (x.value[i] & digit_mask)));

      this.value[j] = (byte) (akku & digit_mask);
      akku = (short) ((akku >> digit_len) & digit_mask);
    }
    // add carry at position j
    akku = (short) (akku + (short) (this.value[j] & digit_mask));
    this.value[j] = (byte) (akku & digit_mask);
    // BUGUG: assert no overflow
  }

  /**
   * Division of this bignat by provided other bignat.
   * @param other value of divisor
   */
  public void divide(Bignat other) {
    ecc.bnh.fnc_divide_tmpThis.lock();
    ecc.bnh.fnc_divide_tmpThis.clone(this);
    ecc.bnh.fnc_divide_tmpThis.remainder_divide(other, this);
    this.clone(ecc.bnh.fnc_divide_tmpThis);
    ecc.bnh.fnc_divide_tmpThis.unlock();
  }

  /**
   * Computes base^exp and stores result into this bignat
   * @param base value of base
   * @param exp value of exponent
   */
  public void exponentiation(Bignat base, Bignat exp) {
    this.one();
    ecc.bnh.fnc_exponentiation_i.lock();
    ecc.bnh.fnc_exponentiation_i.set_size(exp.length());
    ecc.bnh.fnc_exponentiation_i.zero();
    ecc.bnh.fnc_exponentiation_tmp.lock();
    ecc.bnh.fnc_exponentiation_tmp.set_size((short) (2 * this.length()));
    for (; ecc.bnh.fnc_exponentiation_i.lesser(exp); ecc.bnh.fnc_exponentiation_i.increment_one()) {
      ecc.bnh.fnc_exponentiation_tmp.mult(this, base);
      this.copy(ecc.bnh.fnc_exponentiation_tmp);
    }
    ecc.bnh.fnc_exponentiation_i.unlock();
    ecc.bnh.fnc_exponentiation_tmp.unlock();
  }

  /**
   * Multiplication. Automatically selects fastest available algorithm.
   * Stores {@code x * y} in this. To ensure this is big
   * enough for the result it is asserted that the size of this is greater
   * than or equal to the sum of the sizes of {@code x} and {@code y}.
   *
   * @param x
   *            first factor
   * @param y
   *            second factor
   */
  public void mult(Bignat x, Bignat y) {
    if (!ecc.FLAG_FAST_MULT_VIA_RSA || x.length() < ecc.FAST_MULT_VIA_RSA_TRESHOLD_LENGTH) {
      // If not supported, use slow multiplication
      // Use slow multiplication also when numbers are small => faster to do in software
      mult_schoolbook(x, y);
    }
    else {
      mult_rsa_trick(x, y, null, null);
    }
  }

  /**
   * Slow schoolbook algorithm for multiplication
   * @param x first number to multiply
   * @param y second number to multiply
   */
  public void mult_schoolbook(Bignat x, Bignat y) {
    this.zero(); // important to keep, used in exponentiation()
    for (short i = (short) (y.size - 1); i >= 0; i--) {
      this.times_add_shift(x, (short) (y.size - 1 - i), (short) (y.value[i] & digit_mask));
    }
  }

  /**
   * Performs multiplication of two bignats x and y and stores result into
   * this. RSA engine is used to speedup operation.
   * @param x first value to multiply
   * @param y second value to multiply
   */
  public void mult_RSATrick(Bignat x, Bignat y) {
    mult_rsa_trick(x, y, null, null);
  }

  /**
   * Performs multiplication of two bignats x and y and stores result into this.
   * RSA engine is used to speedup operation for large values.
   * Idea of speedup:
   * We need to mutiply x.y where both x and y are 32B
   * (x + y)^2 == x^2 + y^2 + 2xy
   * Fast RSA engine is available (a^b mod n)
   * n can be set bigger than 64B => a^b mod n == a^b
   * [(x + y)^2 mod n] - [x^2 mod n] - [y^2 mod n] => 2xy where [] means single RSA operation
   * 2xy / 2 => result of mult(x,y)
   * Note: if multiplication is used with either x or y argument same repeatedly,
   * [x^2 mod n] or [y^2 mod n] can be precomputed and passed as arguments x_pow_2 or y_pow_2
   *
   * @param x first value to multiply
   * @param y second value to multiply
   * @param x_pow_2 if not null, array with precomputed value x^2 is expected
   * @param y_pow_2 if not null, array with precomputed value y^2 is expected
   */
  public void mult_rsa_trick(Bignat x, Bignat y, byte[] x_pow_2, byte[] y_pow_2) {
    short xOffset;
    short yOffset;

    // x+y
    Util.arrayFillNonAtomic(ecc.bnh.fnc_mult_resultArray1, (short) 0, (short) ecc.bnh.fnc_mult_resultArray1.length, (byte) 0);
    // We must copy bigger number first
    if (x.size > y.size) {
      // Copy x to the end of mult_resultArray
      xOffset = (short) (ecc.bnh.fnc_mult_resultArray1.length - x.length());
      Util.arrayCopyNonAtomic(x.value, (short) 0, ecc.bnh.fnc_mult_resultArray1, xOffset, x.length());
      if (add(ecc.bnh.fnc_mult_resultArray1, xOffset, x.size, y.value, (short) 0, y.size)) {
        xOffset--;
        ecc.bnh.fnc_mult_resultArray1[xOffset] = 0x01;
      }
    } else {
      // Copy x to the end of mult_resultArray
      yOffset = (short) (ecc.bnh.fnc_mult_resultArray1.length - y.length());
      Util.arrayCopyNonAtomic(y.value, (short) 0, ecc.bnh.fnc_mult_resultArray1, yOffset, y.length());
      if (add(ecc.bnh.fnc_mult_resultArray1, yOffset, y.size, x.value, (short) 0, x.size)) {
        yOffset--;
        ecc.bnh.fnc_mult_resultArray1[yOffset] = 0x01; // add carry if occured
      }
    }

    // ((x+y)^2)
    ecc.bnh.fnc_mult_cipher.doFinal(ecc.bnh.fnc_mult_resultArray1, (byte) 0, (short) ecc.bnh.fnc_mult_resultArray1.length, ecc.bnh.fnc_mult_resultArray1, (short) 0);

    // x^2
    if (x_pow_2 == null) {
      // x^2 is not precomputed
      Util.arrayFillNonAtomic(ecc.bnh.fnc_mult_resultArray2, (short) 0, (short) ecc.bnh.fnc_mult_resultArray2.length, (byte) 0);
      xOffset = (short) (ecc.bnh.fnc_mult_resultArray2.length - x.length());
      Util.arrayCopyNonAtomic(x.value, (short) 0, ecc.bnh.fnc_mult_resultArray2, xOffset, x.length());
      ecc.bnh.fnc_mult_cipher.doFinal(ecc.bnh.fnc_mult_resultArray2, (byte) 0, (short) ecc.bnh.fnc_mult_resultArray2.length, ecc.bnh.fnc_mult_resultArray2, (short) 0);
    } else {
      // x^2 is precomputed
      if ((short) x_pow_2.length != (short) ecc.bnh.fnc_mult_resultArray2.length) {
        Util.arrayFillNonAtomic(ecc.bnh.fnc_mult_resultArray2, (short) 0, (short) ecc.bnh.fnc_mult_resultArray2.length, (byte) 0);
        xOffset = (short) ((short) ecc.bnh.fnc_mult_resultArray2.length - (short) x_pow_2.length);
      } else {
        xOffset = 0;
      }
      Util.arrayCopyNonAtomic(x_pow_2, (short) 0, ecc.bnh.fnc_mult_resultArray2, xOffset, (short) x_pow_2.length);
    }
    // ((x+y)^2) - x^2
    subtract(ecc.bnh.fnc_mult_resultArray1, (short) 0, (short) ecc.bnh.fnc_mult_resultArray1.length, ecc.bnh.fnc_mult_resultArray2, (short) 0, (short) ecc.bnh.fnc_mult_resultArray2.length);

    // y^2
    if (x_pow_2 == null) {
      // y^2 is not precomputed
      Util.arrayFillNonAtomic(ecc.bnh.fnc_mult_resultArray2, (short) 0, (short) ecc.bnh.fnc_mult_resultArray2.length, (byte) 0);
      yOffset = (short) (ecc.bnh.fnc_mult_resultArray2.length - y.length());
      Util.arrayCopyNonAtomic(y.value, (short) 0, ecc.bnh.fnc_mult_resultArray2, yOffset, y.length());
      ecc.bnh.fnc_mult_cipher.doFinal(ecc.bnh.fnc_mult_resultArray2, (byte) 0, (short) ecc.bnh.fnc_mult_resultArray2.length, ecc.bnh.fnc_mult_resultArray2, (short) 0);
    } else {
      // y^2 is precomputed
      if ((short) y_pow_2.length != (short) ecc.bnh.fnc_mult_resultArray2.length) {
        Util.arrayFillNonAtomic(ecc.bnh.fnc_mult_resultArray2, (short) 0, (short) ecc.bnh.fnc_mult_resultArray2.length, (byte) 0);
        yOffset = (short) ((short) ecc.bnh.fnc_mult_resultArray2.length - (short) y_pow_2.length);
      } else {
        yOffset = 0;
      }
      Util.arrayCopyNonAtomic(y_pow_2, (short) 0, ecc.bnh.fnc_mult_resultArray2, yOffset, (short) y_pow_2.length);
    }


    // {(x+y)^2) - x^2} - y^2
    subtract(ecc.bnh.fnc_mult_resultArray1, (short) 0, (short) ecc.bnh.fnc_mult_resultArray1.length, ecc.bnh.fnc_mult_resultArray2, (short) 0, (short) ecc.bnh.fnc_mult_resultArray2.length);

    // we now have 2xy in mult_resultArray, divide it by 2 => shift by one bit and fill back into this
    short multOffset = (short) ((short) ecc.bnh.fnc_mult_resultArray1.length - 1);
    short res = 0;
    short res2 = 0;
    // this.length() must be different from multOffset, set proper ending condition
    short stopOffset = 0;
    if (this.length() > multOffset) {
      stopOffset = (short) (this.length() - multOffset); // only part of this.value will be filled
    } else {
      stopOffset = 0; // whole this.value will be filled
    }
    if (stopOffset > 0) {
      Util.arrayFillNonAtomic(this.value, (short) 0, stopOffset, (byte) 0);
    }
    for (short i = (short) (this.length() - 1); i >= stopOffset; i--) {
      res = (short) (ecc.bnh.fnc_mult_resultArray1[multOffset] & 0xff);
      res = (short) (res >> 1);
      res2 = (short) (ecc.bnh.fnc_mult_resultArray1[(short) (multOffset - 1)] & 0xff);
      res2 = (short) (res2 << 7);
      this.value[i] = (byte) (short) (res | res2);
      multOffset--;
    }
  }

  /**
   * Multiplication of bignats x and y computed by modulo {@code modulo}.
   * The result is stored to this.
   * @param x first value to multiply
   * @param y second value to multiply
   * @param modulo value of modulo
   */
  public void mod_mult(Bignat x, Bignat y, Bignat modulo) {
    ecc.bnh.fnc_mod_mult_tmpThis.lock();
    ecc.bnh.fnc_mod_mult_tmpThis.resize_to_max(false);
    // Perform fast multiplication using RSA trick
    ecc.bnh.fnc_mod_mult_tmpThis.mult(x, y);
    // Compute modulo
    ecc.bnh.fnc_mod_mult_tmpThis.mod(modulo);
    ecc.bnh.fnc_mod_mult_tmpThis.shrink();
    this.clone(ecc.bnh.fnc_mod_mult_tmpThis);
    ecc.bnh.fnc_mod_mult_tmpThis.unlock();
  }
  // Potential speedup for  modular multiplication
  // Binomial theorem: (op1 + op2)^2 - (op1 - op2)^2 = 4 * op1 * op2 mod (mod)



  /**
   * One digit left shift.
   * <P>
   * Asserts that the first digit is zero.
   */
  public void shift_left() {
    // NOTE: assumes that overlapping src and dest arrays are properly handled by Util.arrayCopyNonAtomic
    Util.arrayCopyNonAtomic(this.value, (short) 1, this.value, (short) 0, (short) (size - 1));
    value[(short) (size - 1)] = 0;
  }

  /**
   * Optimized division by value two
   */
  private void divide_by_2() {
    short tmp = 0;
    short tmp2 = 0;
    short carry = 0;
    for (short i = 0; i < this.size; i++) {
      tmp = (short) (this.value[i] & 0xff);
      tmp2 = tmp;
      tmp >>=1; // shift by 1 => divide by 2
      this.value[i] = (byte) (tmp | carry);
      carry = (short) (tmp2 & 0x01); // save lowest bit
      carry <<= 7; // shifted to highest position
    }
  }

  //
  /**
   * Computes square root of provided bignat which MUST be prime using Tonelli
   * Shanks Algorithm. The result (one of the two roots) is stored to this.
   * @param p value to compute square root from
   */
  public void sqrt_FP(Bignat p) {
    //1. By factoring out powers of 2, find Q and S such that p-1=Q2^S p-1=Q*2^S and Q is odd
    ecc.bnh.fnc_sqrt_p_1.lock();
    ecc.bnh.fnc_sqrt_p_1.clone(p);
    ecc.bnh.fnc_sqrt_p_1.decrement_one();

    //Compute Q
    ecc.bnh.fnc_sqrt_Q.lock();
    ecc.bnh.fnc_sqrt_Q.clone(ecc.bnh.fnc_sqrt_p_1);
    ecc.bnh.fnc_sqrt_Q.divide_by_2(); //Q /= 2

    //Compute S
    ecc.bnh.fnc_sqrt_S.lock();
    ecc.bnh.fnc_sqrt_S.set_size(p.length());
    ecc.bnh.fnc_sqrt_S.zero();
    ecc.bnh.fnc_sqrt_tmp.lock();
    ecc.bnh.fnc_sqrt_tmp.set_size(p.length());
    ecc.bnh.fnc_sqrt_tmp.zero();

    while (!ecc.bnh.fnc_sqrt_tmp.same_value(ecc.bnh.fnc_sqrt_Q)) {
      ecc.bnh.fnc_sqrt_S.increment_one();
      ecc.bnh.fnc_sqrt_tmp.mod_mult(ecc.bnh.fnc_sqrt_S, ecc.bnh.fnc_sqrt_Q, p);
    }
    ecc.bnh.fnc_sqrt_tmp.unlock();
    ecc.bnh.fnc_sqrt_S.unlock();

    //2. Find the first quadratic non-residue z by brute-force search
    ecc.bnh.fnc_sqrt_exp.lock();
    ecc.bnh.fnc_sqrt_exp.clone(ecc.bnh.fnc_sqrt_p_1);
    ecc.bnh.fnc_sqrt_exp.divide_by_2();

    ecc.bnh.fnc_sqrt_z.lock();
    ecc.bnh.fnc_sqrt_z.set_size(p.length());
    ecc.bnh.fnc_sqrt_z.one();
    ecc.bnh.fnc_sqrt_tmp.lock();
    ecc.bnh.fnc_sqrt_tmp.zero();
    ecc.bnh.fnc_sqrt_tmp.copy(ecc.bnh.ONE);

    while (!ecc.bnh.fnc_sqrt_tmp.same_value(ecc.bnh.fnc_sqrt_p_1)) {
      ecc.bnh.fnc_sqrt_z.increment_one();
      ecc.bnh.fnc_sqrt_tmp.copy(ecc.bnh.fnc_sqrt_z);
      ecc.bnh.fnc_sqrt_tmp.mod_exp(ecc.bnh.fnc_sqrt_exp, p);
    }

    ecc.bnh.fnc_sqrt_p_1.unlock();
    ecc.bnh.fnc_sqrt_tmp.unlock();
    ecc.bnh.fnc_sqrt_z.unlock();
    ecc.bnh.fnc_sqrt_exp.copy(ecc.bnh.fnc_sqrt_Q);
    ecc.bnh.fnc_sqrt_Q.unlock();
    ecc.bnh.fnc_sqrt_exp.increment_one();
    ecc.bnh.fnc_sqrt_exp.divide_by_2();

    this.mod(p);
    this.mod_exp(ecc.bnh.fnc_sqrt_exp, p);
    ecc.bnh.fnc_sqrt_exp.unlock();
  } // end void sqrt(Bignat p)


  /**
   * Computes and stores modulo of this bignat.
   * @param modulo value of modulo
   */
  public void mod(Bignat modulo) {
    this.remainder_divide(modulo, null);
    // NOTE: attempt made to utilize crypto co-processor in pow2Mod_RSATrick_worksOnlyAbout30pp, but doesn't work for all inputs
  }



  /**
   * Computes inversion of this bignat taken modulo {@code modulo}.
   * The result is stored into this.
   * @param modulo value of modulo
   */
  public void mod_inv(Bignat modulo) {
    ecc.bnh.fnc_mod_minus_2.lock();
    ecc.bnh.fnc_mod_minus_2.clone(modulo);
    ecc.bnh.fnc_mod_minus_2.decrement_one();
    ecc.bnh.fnc_mod_minus_2.decrement_one();

    mod_exp(ecc.bnh.fnc_mod_minus_2, modulo);
    ecc.bnh.fnc_mod_minus_2.unlock();
  }

  /**
   * Computes {@code res := this ** exponent mod modulo} and store results into this.
   * Uses RSA engine to quickly compute this^exponent % modulo
   * @param exponent value of exponent
   * @param modulo value of modulo
   */
  public void mod_exp(Bignat exponent, Bignat modulo) {
    short tmp_size = (short)(ecc.MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8);
    ecc.bnh.fnc_mod_exp_modBN.lock();
    ecc.bnh.fnc_mod_exp_modBN.set_size(tmp_size);

    short len = n_mod_exp(tmp_size, this, exponent.as_byte_array(), exponent.length(), modulo, ecc.bnh.fnc_mod_exp_modBN.value, (short) 0);
    if (len != tmp_size) {
      Util.arrayFillNonAtomic(ecc.bnh.fnc_deep_resize_tmp, (short) 0, (short) ecc.bnh.fnc_deep_resize_tmp.length, (byte) 0);
      Util.arrayCopyNonAtomic(ecc.bnh.fnc_mod_exp_modBN.value, (short) 0, ecc.bnh.fnc_deep_resize_tmp, (short) (tmp_size - len), len);
      Util.arrayCopyNonAtomic(ecc.bnh.fnc_deep_resize_tmp, (short) 0, ecc.bnh.fnc_mod_exp_modBN.value, (short) 0, tmp_size);
    }
    ecc.bnh.fnc_mod_exp_modBN.mod(modulo);
    ecc.bnh.fnc_mod_exp_modBN.shrink();
    this.clone(ecc.bnh.fnc_mod_exp_modBN);
    ecc.bnh.fnc_mod_exp_modBN.unlock();
  }


  public void mod_exp2(Bignat modulo) {
    mod_exp(ecc.bnh.TWO, modulo);
  }

  /**
   * Calculates {@code res := base ** exp mod mod} using RSA engine.
   * Requirements:
   * 1. Modulo must be either 521, 1024, 2048 or other lengths supported by RSA (see appendzeros() and mod() method)
   * 2. Base must have the same size as modulo (see prependzeros())
   * @param baseLen   length of base rounded to size of RSA engine
   * @param base      value of base (if size is not equal to baseLen then zeroes are appended)
   * @param exponent  array with exponent
   * @param exponentLen length of exponent
   * @param modulo    value of modulo
   * @param resultArray array for the computed result
   * @param resultOffset start offset of resultArray
   */
  private short n_mod_exp(short baseLen, Bignat base, byte[] exponent, short exponentLen, Bignat modulo, byte[] resultArray, short resultOffset) {
    // Verify if pre-allocated engine match the required values
    if (ecc.bnh.fnc_NmodE_pubKey.getSize() < (short) (modulo.length() * 8)) {
      // attempt to perform modulu with higher or smaller than supported length - try change constant MODULO_ENGINE_MAX_LENGTH
      ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
    }
    if (ecc.bnh.fnc_NmodE_pubKey.getSize() < (short) (base.length() * 8)) {
      ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
    }
    // Potential problem: we are changing key value for publicKey already used before with occ.bnHelper.modCipher.
    // Simulator and potentially some cards fail to initialize this new value properly (probably assuming that same key object will always have same value)
    // Fix (if problem occure): generate new key object: RSAPublicKey publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) (baseLen * 8), false);

    ecc.bnh.fnc_NmodE_pubKey.setExponent(exponent, (short) 0, exponentLen);
    modulo.append_zeros(baseLen, ecc.bnh.fnc_deep_resize_tmp, (short) 0);
    ecc.bnh.fnc_NmodE_pubKey.setModulus(ecc.bnh.fnc_deep_resize_tmp, (short) 0, baseLen);
    ecc.bnh.fnc_NmodE_cipher.init(ecc.bnh.fnc_NmodE_pubKey, Cipher.MODE_DECRYPT);
    base.prepend_zeros(baseLen, ecc.bnh.fnc_deep_resize_tmp, (short) 0);
    // BUGBUG: Check if input is not all zeroes (causes out-of-bound exception on some cards)
    short len = ecc.bnh.fnc_NmodE_cipher.doFinal(ecc.bnh.fnc_deep_resize_tmp, (short) 0, baseLen, resultArray, resultOffset);
    return len;
  }

  /**
   * Negate current Bignat modulo provided modulus
   *
   * @param mod value of modulus
   */
  public void mod_negate(Bignat mod) {
    ecc.bnh.fnc_negate_tmp.lock();
    ecc.bnh.fnc_negate_tmp.set_size(mod.length());
    ecc.bnh.fnc_negate_tmp.copy(mod); //-y=mod-y

    if (this.lesser(mod)) { // y<mod
      ecc.bnh.fnc_negate_tmp.subtract(this);//-y=mod-y
      this.copy(ecc.bnh.fnc_negate_tmp);
    } else {// y>=mod
      this.mod(mod);//-y=y-mod
      ecc.bnh.fnc_negate_tmp.subtract(this);
      this.copy(ecc.bnh.fnc_negate_tmp);
    }
    ecc.bnh.fnc_negate_tmp.unlock();
  }


  /**
   * Allocates required underlying storage array with given maximum size and
   * allocator type (RAM or EEROM). Maximum size can be increased only by
   * future reallocation if allowed by ALLOW_RUNTIME_REALLOCATION flag
   *
   * @param maxSize maximum size of this Bignat
   * @param allocatorType memory allocator type. If
   * JCSystem.MEMORY_TYPE_PERSISTENT then memory is allocated in EEPROM. Use
   * JCSystem.CLEAR_ON_RESET or JCSystem.CLEAR_ON_DESELECT for allocation in
   * RAM with corresponding clearing behaviour.
   */
  private void allocate_storage_array(short maxSize, byte allocatorType) {
    this.size = maxSize;
    this.max_size = maxSize;
    this.allocatorType = allocatorType;
    this.value = ecc.memAlloc.allocateByteArray(this.max_size, allocatorType);
  }

  /**
   * Set content of Bignat internal array
   *
   * @param from_array_length available data in {@code from_array}
   * @param this_offset offset where data should be stored
   * @param from_array data array to deserialize from
   * @param from_array_offset offset in {@code from_array}
   * @return the number of shorts actually read, except for the case where
   * deserialization finished by reading precisely {@code len} shorts, in this
   * case {@code len + 1} is returned.
   */
  public short from_byte_array(short from_array_length, short this_offset, byte[] from_array, short from_array_offset) {
    short max
        = (short) (this_offset + from_array_length) <= this.size
        ? from_array_length : (short) (this.size - this_offset);
    Util.arrayCopyNonAtomic(from_array, from_array_offset, value, this_offset, max);
    if ((short) (this_offset + from_array_length) == this.size) {
      return (short) (from_array_length + 1);
    } else {
      return max;
    }
  }

  /**
   * Set content of Bignat internal array
   *
   * @param this_offset offset where data should be stored
   * @param from_array data array to deserialize from
   * @param from_array_length available data in {@code from_array}
   * @param from_array_offset offset in {@code from_array}
   * @return the number of shorts actually read, except for the case where
   * deserialization finished by reading precisely {@code len} shorts, in this
   * case {@code len + 1} is returned.
   */
  public short set_from_byte_array(short this_offset, byte[] from_array, short from_array_offset, short from_array_length) {
    return from_byte_array(from_array_length, this_offset, from_array, from_array_offset);
  }

  /**
   * Set content of Bignat internal array
   *
   * @param from_array data array to deserialize from
   * @return the number of shorts actually read
   */
  public short from_byte_array(byte[] from_array) {
    return this.from_byte_array((short) from_array.length, (short) (this.value.length - from_array.length), from_array, (short) 0);
  }
}

package im.status.wallet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECPoint {
  private final ECConfig ecc;

  private ECPublicKey         thePoint;
  private KeyPair             thePointKeyPair;
  private final ECCurve       theCurve;

  /**
   * Creates new ECPoint object for provided {@code curve}. Random initial point value is generated.
   * The point will use helper structures from provided ECPoint_Helper object.
   * @param curve point's elliptic curve
   * @param ecc object with preallocated helper objects and memory arrays
   */
  public ECPoint(ECCurve curve, ECConfig ecc) {
    this.theCurve = curve;
    this.ecc = ecc;
    updatePointObjects();
  }

  /**
   * Returns length of this point in bytes.
   *
   * @return
   */
  public short length() {
    return (short) (thePoint.getSize() / 8);
  }

  /**
   * Properly updates all point values in case of a change of an underlying curve.
   * New random point value is generated.
   */
  public final void updatePointObjects() {
    this.thePointKeyPair = this.theCurve.newKeyPair(this.thePointKeyPair);
    this.thePoint = (ECPublicKey) thePointKeyPair.getPublic();
  }
  /**
   * Generates new random point value.
   */
  public void randomize(){
    if (this.thePointKeyPair == null) {
      this.thePointKeyPair = this.theCurve.newKeyPair(this.thePointKeyPair);
      this.thePoint = (ECPublicKey) thePointKeyPair.getPublic();
    }
    else {
      this.thePointKeyPair.genKeyPair();
    }
  }

  /**
   * Copy value of provided point into this. This and other point must have
   * curve with same parameters, only length is checked.
   * @param other point to be copied
   */
  public void copy(ECPoint other) {
    if (this.length() != other.length()) {
      ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
    }
    short len = other.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
    this.setW(ecc.ech.uncompressed_point_arr1, (short) 0, len);
  }

  /**
   * Set this point value (parameter W) from array with value encoded as per ANSI X9.62.
   * The uncompressed form is always supported. If underlying native JavaCard implementation
   * of {@code ECPublickKey} supports compressed points, then this method accepts also compressed points.
   * @param buffer array with serialized point
   * @param offset start offset within input array
   * @param length length of point
   */
  public void setW(byte[] buffer, short offset, short length) {
    this.thePoint.setW(buffer, offset, length);
  }

  /**
   * Returns current value of this point.
   * @param buffer    memory array where to store serailized point value
   * @param offset    start offset for output serialized point
   * @return length of serialized point (number of bytes)
   */
  public short getW(byte[] buffer, short offset) {
    return thePoint.getW(buffer, offset);
  }

  /**
   * Returns this point value as ECPublicKey object. No copy of point is made
   * before return, so change of returned object will also change this point value.
   * @return point as ECPublicKey object
   */
  public ECPublicKey asPublicKey() {
    return this.thePoint;
  }

  /**
   * Returns curve associated with this point. No copy of curve is made
   * before return, so change of returned object will also change curve for
   * this point.
   *
   * @return curve as ECCurve object
   */
  public ECCurve getCurve() {
    return theCurve;
  }

  /**
   * Returns the X coordinate of this point in uncompressed form.
   * @param buffer output array for X coordinate
   * @param offset start offset within output array
   * @return length of X coordinate (in bytes)
   */
  public short getX(byte[] buffer, short offset) {
    thePoint.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
    Util.arrayCopyNonAtomic(ecc.ech.uncompressed_point_arr1, (short) 1, buffer, offset, this.theCurve.COORD_SIZE);
    return this.theCurve.COORD_SIZE;
  }

  /**
   * Returns the Y coordinate of this point in uncompressed form.
   *
   * @param buffer output array for Y coordinate
   * @param offset start offset within output array
   * @return length of Y coordinate (in bytes)
   */
  public short getY(byte[] buffer, short offset) {
    thePoint.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
    Util.arrayCopyNonAtomic(ecc.ech.uncompressed_point_arr1, (short)(1 + this.theCurve.COORD_SIZE), buffer, offset, this.theCurve.COORD_SIZE);
    return this.theCurve.COORD_SIZE;
  }
  /**
   * Returns the Y coordinate of this point in form of Bignat object.
   *
   * @param yCopy Bignat object which will be set with value of this point
   */
  public void getY(Bignat yCopy) {
    yCopy.set_size(this.getY(yCopy.as_byte_array(), (short) 0));
  }




  /**
   * Doubles the current value of this point.
   */
  public void makeDouble() {
    // doubling via add sometimes causes exception inside KeyAgreement engine
    // this.add(this);
    // Use bit slower, but more robust version via multiplication by 2
    this.multiplication(ecc.bnh.TWO);
  }

  /**
   * Adds this (P) and provided (Q) point. Stores a resulting value into this point.
   * @param other point to be added to this.
   */
  public void add(ECPoint other) {
    this.thePoint.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
    ecc.ech.fnc_add_x_p.lock();
    ecc.ech.fnc_add_x_p.set_size(this.theCurve.COORD_SIZE);
    ecc.ech.fnc_add_x_p.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ecc.ech.uncompressed_point_arr1, (short) 1);
    ecc.ech.fnc_add_y_p.lock();
    ecc.ech.fnc_add_y_p.set_size(this.theCurve.COORD_SIZE);
    ecc.ech.fnc_add_y_p.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ecc.ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));

    // l = (y_q-y_p)/(x_q-x_p))
    // x_r = l^2 - x_p -x_q
    // y_r = l(x_p-x_r)-y_p

    // P+Q=R
    ecc.ech.fnc_add_nominator.lock();
    ecc.ech.fnc_add_denominator.lock();
    if (this == other) {
      //lambda = (3(x_p^2)+a)/(2y_p)
      //(3(x_p^2)+a)
      ecc.ech.fnc_add_nominator.clone(ecc.ech.fnc_add_x_p);
      ecc.ech.fnc_add_nominator.mod_exp(ecc.bnh.TWO, this.theCurve.pBN);
      ecc.ech.fnc_add_nominator.mod_mult(ecc.ech.fnc_add_nominator, ecc.bnh.THREE, this.theCurve.pBN);
      ecc.ech.fnc_add_nominator.mod_add(this.theCurve.aBN, this.theCurve.pBN);
      // (2y_p)
      ecc.ech.fnc_add_denominator.clone(ecc.ech.fnc_add_y_p);
      ecc.ech.fnc_add_denominator.mod_mult(ecc.ech.fnc_add_y_p, ecc.bnh.TWO, this.theCurve.pBN);
      ecc.ech.fnc_add_denominator.mod_inv(this.theCurve.pBN);

    } else {
      // lambda=(y_q-y_p)/(x_q-x_p) mod p
      other.thePoint.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
      ecc.ech.fnc_add_x_q.lock();
      ecc.ech.fnc_add_x_q.set_size(this.theCurve.COORD_SIZE);
      ecc.ech.fnc_add_x_q.from_byte_array(other.theCurve.COORD_SIZE, (short) 0, ecc.ech.uncompressed_point_arr1, (short) 1);
      ecc.ech.fnc_add_nominator.set_size(this.theCurve.COORD_SIZE);
      ecc.ech.fnc_add_nominator.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ecc.ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));

      ecc.ech.fnc_add_nominator.mod(this.theCurve.pBN);

      ecc.ech.fnc_add_nominator.mod_sub(ecc.ech.fnc_add_y_p, this.theCurve.pBN);

      // (x_q-x_p)
      ecc.ech.fnc_add_denominator.clone(ecc.ech.fnc_add_x_q);
      ecc.ech.fnc_add_denominator.mod(this.theCurve.pBN);
      ecc.ech.fnc_add_denominator.mod_sub(ecc.ech.fnc_add_x_p, this.theCurve.pBN);
      ecc.ech.fnc_add_denominator.mod_inv(this.theCurve.pBN);
    }

    ecc.ech.fnc_add_lambda.lock();
    ecc.ech.fnc_add_lambda.resize_to_max(false);
    ecc.ech.fnc_add_lambda.zero();
    ecc.ech.fnc_add_lambda.mod_mult(ecc.ech.fnc_add_nominator, ecc.ech.fnc_add_denominator, this.theCurve.pBN);
    ecc.ech.fnc_add_nominator.unlock();
    ecc.ech.fnc_add_denominator.unlock();

    // (x_p,y_p)+(x_q,y_q)=(x_r,y_r)
    // lambda=(y_q-y_p)/(x_q-x_p)

    //x_r=lambda^2-x_p-x_q
    ecc.ech.fnc_add_x_r.lock();
    if (this == other) {
      short len = this.multiplication_x(ecc.bnh.TWO, ecc.ech.fnc_add_x_r.as_byte_array(), (short) 0);
      ecc.ech.fnc_add_x_r.set_size(len);
    } else {
      ecc.ech.fnc_add_x_r.clone(ecc.ech.fnc_add_lambda);
      //m_occ.ecHelper.fnc_add_x_r.mod_exp(occ.bnHelper.TWO, this.TheCurve.pBN);
      ecc.ech.fnc_add_x_r.mod_exp2(this.theCurve.pBN);
      ecc.ech.fnc_add_x_r.mod_sub(ecc.ech.fnc_add_x_p, this.theCurve.pBN);
      ecc.ech.fnc_add_x_r.mod_sub(ecc.ech.fnc_add_x_q, this.theCurve.pBN);
      ecc.ech.fnc_add_x_q.unlock();
    }
    //y_r=lambda(x_p-x_r)-y_p
    ecc.ech.fnc_add_y_r.lock();
    ecc.ech.fnc_add_y_r.clone(ecc.ech.fnc_add_x_p);
    ecc.ech.fnc_add_x_p.unlock();
    ecc.ech.fnc_add_y_r.mod_sub(ecc.ech.fnc_add_x_r, this.theCurve.pBN);
    ecc.ech.fnc_add_y_r.mod_mult(ecc.ech.fnc_add_y_r, ecc.ech.fnc_add_lambda, this.theCurve.pBN);
    ecc.ech.fnc_add_lambda.unlock();
    ecc.ech.fnc_add_y_r.mod_sub(ecc.ech.fnc_add_y_p, this.theCurve.pBN);
    ecc.ech.fnc_add_y_p.unlock();

    ecc.ech.uncompressed_point_arr1[0] = (byte)0x04;
    // If x_r.length() and y_r.length() is smaller than this.TheCurve.COORD_SIZE due to leading zeroes which were shrinked before, then we must add these back
    ecc.ech.fnc_add_x_r.prepend_zeros(this.theCurve.COORD_SIZE, ecc.ech.uncompressed_point_arr1, (short) 1);
    ecc.ech.fnc_add_x_r.unlock();
    ecc.ech.fnc_add_y_r.prepend_zeros(this.theCurve.COORD_SIZE, ecc.ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
    ecc.ech.fnc_add_y_r.unlock();
    this.setW(ecc.ech.uncompressed_point_arr1, (short) 0, this.theCurve.POINT_SIZE);
  }

  /**
   * Multiply value of this point by provided scalar. Stores the result into
   * this point.
   *
   * @param scalar value of scalar for multiplication
   */
  public void multiplication(byte[] scalar, short scalarOffset, short scalarLen) {
    ecc.ech.fnc_multiplication_scalar.lock();
    ecc.ech.fnc_multiplication_scalar.set_size(scalarLen);
    ecc.ech.fnc_multiplication_scalar.from_byte_array(scalarLen, (short) 0, scalar, scalarOffset);
    multiplication(ecc.ech.fnc_multiplication_scalar);
    ecc.ech.fnc_multiplication_scalar.unlock();
  }
  /**
   * Multiply value of this point by provided scalar. Stores the result into this point.
   * @param scalar value of scalar for multiplication
   */
  public void multiplication(Bignat scalar) {
    ecc.ech.fnc_multiplication_x.lock();
    short len = this.multiplication_x(scalar, ecc.ech.fnc_multiplication_x.as_byte_array(), (short) 0);
    ecc.ech.fnc_multiplication_x.set_size(len);

    //Y^2 = X^3 + XA + B = x(x^2+A)+B
    ecc.ech.fnc_multiplication_y_sq.lock();
    ecc.ech.fnc_multiplication_y_sq.clone(ecc.ech.fnc_multiplication_x);
    ecc.ech.fnc_multiplication_y_sq.mod_exp(ecc.bnh.TWO, this.theCurve.pBN);
    ecc.ech.fnc_multiplication_y_sq.mod_add(this.theCurve.aBN, this.theCurve.pBN);
    ecc.ech.fnc_multiplication_y_sq.mod_mult(ecc.ech.fnc_multiplication_y_sq, ecc.ech.fnc_multiplication_x, this.theCurve.pBN);
    ecc.ech.fnc_multiplication_y_sq.mod_add(this.theCurve.bBN, this.theCurve.pBN);
    ecc.ech.fnc_multiplication_y1.lock();
    ecc.ech.fnc_multiplication_y1.clone(ecc.ech.fnc_multiplication_y_sq);
    ecc.ech.fnc_multiplication_y_sq.unlock();
    ecc.ech.fnc_multiplication_y1.sqrt_FP(this.theCurve.pBN);

    // Construct public key with <x, y_1>
    ecc.ech.uncompressed_point_arr1[0] = 0x04;
    ecc.ech.fnc_multiplication_x.prepend_zeros(this.theCurve.COORD_SIZE, ecc.ech.uncompressed_point_arr1, (short) 1);
    ecc.ech.fnc_multiplication_x.unlock();
    ecc.ech.fnc_multiplication_y1.prepend_zeros(this.theCurve.COORD_SIZE, ecc.ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));
    this.setW(ecc.ech.uncompressed_point_arr1, (short) 0, theCurve.POINT_SIZE); //So that we can convert to pub key

    // Check if public point <x, y_1> corresponds to the "secret" (i.e., our scalar)
    if (!SignVerifyECDSA(this.theCurve.bignatAsPrivateKey(scalar), this.asPublicKey(), this.ecc.ech.fnc_SignVerifyECDSA_signEngine, ecc.bnh.fnc_mult_resultArray1)) { //If verification fails, then pick the <x, y_2>
      ecc.ech.fnc_multiplication_y2.lock();
      ecc.ech.fnc_multiplication_y2.clone(this.theCurve.pBN); //y_2 = p - y_1
      ecc.ech.fnc_multiplication_y2.mod_sub(ecc.ech.fnc_multiplication_y1, this.theCurve.pBN);
      ecc.ech.fnc_multiplication_y2.copy_to_buffer(ecc.ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));
      ecc.ech.fnc_multiplication_y2.unlock();
    }
    ecc.ech.fnc_multiplication_y1.unlock();

    this.setW(ecc.ech.uncompressed_point_arr1, (short)0, theCurve.POINT_SIZE);
  }

  /**
   * Multiplies this point value with provided scalar and stores result into provided array.
   * No modification of this point is performed.
   * @param scalar value of scalar for multiplication
   * @param outBuffer output array for resulting value
   * @param outBufferOffset offset within output array
   * @return length of resulting value (in bytes)
   */
  public short multiplication_x(Bignat scalar, byte[] outBuffer, short outBufferOffset) {
    return multiplication_x_KA(scalar, outBuffer, outBufferOffset);
  }


  /**
   * Multiplies this point value with provided scalar and stores result into
   * provided array. No modification of this point is performed.
   * Native KeyAgreement engine is used.
   *
   * @param scalar value of scalar for multiplication
   * @param outBuffer output array for resulting value
   * @param outBufferOffset offset within output array
   * @return length of resulting value (in bytes)
   */
  private short multiplication_x_KA(Bignat scalar, byte[] outBuffer, short outBufferOffset) {
    // NOTE: potential problem on real cards (j2e) - when small scalar is used (e.g., Bignat.TWO), operation sometimes freezes
    theCurve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());

    ecc.ech.fnc_multiplication_x_keyAgreement.init(theCurve.disposable_priv);

    short len = this.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
    len = ecc.ech.fnc_multiplication_x_keyAgreement.generateSecret(ecc.ech.uncompressed_point_arr1, (short) 0, len, outBuffer, outBufferOffset);
    // Return always length of whole coordinate X instead of len - some real cards returns shorter value equal to SHA-1 output size although PLAIN results is filled into buffer (GD60)
    return this.theCurve.COORD_SIZE;
  }

  /**
   * Computes negation of this point.
   */
  public void negate() {
    // Operation will dump point into uncompressed_point_arr, negate Y and restore back
    ecc.ech.fnc_negate_yBN.lock();
    thePoint.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
    ecc.ech.fnc_negate_yBN.set_size(this.theCurve.COORD_SIZE);
    ecc.ech.fnc_negate_yBN.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ecc.ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
    ecc.ech.fnc_negate_yBN.mod_negate(this.theCurve.pBN);

    // Restore whole point back
    ecc.ech.fnc_negate_yBN.prepend_zeros(this.theCurve.COORD_SIZE, ecc.ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
    ecc.ech.fnc_negate_yBN.unlock();
    this.setW(ecc.ech.uncompressed_point_arr1, (short) 0, this.theCurve.POINT_SIZE);
  }

  /**
   * Compares this and provided point for equality. The comparison is made using hash of both values to prevent leak of position of mismatching byte.
   * @param other second point for comparison
   * @return true if both point are exactly equal (same length, same value), false otherwise
   */
  public boolean isEqual(ECPoint other) {
    boolean bResult = false;
    if (this.length() != other.length()) {
      return false;
    }
    else {
      // The comparison is made with hash of point values instead of directly values.
      // This way, offset of first mismatching byte is not leaked via timing side-channel.
      // Additionally, only single array is required for storage of plain point values thus saving some RAM.
      short len = this.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
      ecc.bnh.hashEngine.doFinal(ecc.ech.uncompressed_point_arr1, (short) 0, len, ecc.ech.hashArray, (short) 0);
      len = other.getW(ecc.ech.uncompressed_point_arr1, (short) 0);
      len = ecc.bnh.hashEngine.doFinal(ecc.ech.uncompressed_point_arr1, (short) 0, len, ecc.ech.uncompressed_point_arr1, (short) 0);
      bResult = Util.arrayCompare(ecc.ech.hashArray, (short) 0, ecc.ech.uncompressed_point_arr1, (short) 0, len) == 0;
    }

    return bResult;
  }

  static byte[] msg = {(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03};
  public static boolean SignVerifyECDSA(ECPrivateKey privateKey, ECPublicKey publicKey, Signature signEngine, byte[] tmpSignArray) {
    signEngine.init(privateKey, Signature.MODE_SIGN);
    short signLen = signEngine.sign(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0);
    signEngine.init(publicKey, Signature.MODE_VERIFY);
    return signEngine.verify(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0, signLen);
  }
}

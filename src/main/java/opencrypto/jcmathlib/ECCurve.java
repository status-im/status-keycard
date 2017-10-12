package opencrypto.jcmathlib;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECCurve {
  public final short KEY_LENGTH; //Bits
  public final short POINT_SIZE; //Bytes
  public final short COORD_SIZE; //Bytes

  //Parameters
  public byte[] p = null;
  public byte[] a = null;
  public byte[] b = null;
  public byte[] G = null;
  public byte[] r = null;

  public Bignat pBN;
  public Bignat aBN;
  public Bignat bBN;

  public KeyPair disposable_pair;
  public ECPrivateKey disposable_priv;



  /**
   * Creates new curve object from provided parameters. Either copy of provided
   * arrays is performed (bCopyArgs == true, input arrays can be reused later for other
   * purposes) or arguments are directly stored (bCopyArgs == false, usable for fixed static arrays) .
   * @param bCopyArgs if true, copy of arguments is created, otherwise reference is directly stored
   * @param p_arr array with p
   * @param a_arr array with a
   * @param b_arr array with b
   * @param G_arr array with base point G
   * @param r_arr array with r
   */
  public ECCurve(boolean bCopyArgs, byte[] p_arr, byte[] a_arr, byte[] b_arr, byte[] G_arr, byte[] r_arr, ECConfig ecc) {
    //ECCurve_initialize(p_arr, a_arr, b_arr, G_arr, r_arr);
    this.KEY_LENGTH = (short) (p_arr.length * 8);
    this.POINT_SIZE = (short) G_arr.length;
    this.COORD_SIZE = (short) ((short) (G_arr.length - 1) / 2);

    if (bCopyArgs) {
      // Copy curve parameters into newly allocated arrays in EEPROM (will be only read, not written later => good performance even when in EEPROM)
      this.p = new byte[(short) p_arr.length];
      this.a = new byte[(short) a_arr.length];
      this.b = new byte[(short) b_arr.length];
      this.G = new byte[(short) G_arr.length];
      this.r = new byte[(short) r_arr.length];

      Util.arrayCopyNonAtomic(p_arr, (short) 0, p, (short) 0, (short) p.length);
      Util.arrayCopyNonAtomic(a_arr, (short) 0, a, (short) 0, (short) a.length);
      Util.arrayCopyNonAtomic(b_arr, (short) 0, b, (short) 0, (short) b.length);
      Util.arrayCopyNonAtomic(G_arr, (short) 0, G, (short) 0, (short) G.length);
      Util.arrayCopyNonAtomic(r_arr, (short) 0, r, (short) 0, (short) r.length);
    }
    else {
      // No allocation, store directly provided arrays
      this.p = p_arr;
      this.a = a_arr;
      this.b = b_arr;
      this.G = G_arr;
      this.r = r_arr;
    }

    // We will not modify values of p/a/b during the lifetime of curve => allocate helper bignats directly from the array
    this.pBN = new Bignat(this.p, ecc);
    this.aBN = new Bignat(this.a, ecc);
    this.bBN = new Bignat(this.b, ecc);

    this.disposable_pair = this.newKeyPair(null);
    this.disposable_priv = (ECPrivateKey) this.disposable_pair.getPrivate();
  }

  /**
   * Refresh critical information stored in RAM for performance reasons after a card reset (RAM was cleared).
   */
  public void updateAfterReset() {
    this.pBN.from_byte_array(this.p);
    this.aBN.from_byte_array(this.a);
    this.bBN.from_byte_array(this.b);
  }

  /**
   * Creates a new keyPair based on this curve parameters. KeyPair object is reused if provided. Fresh keyPair value is generated.
   * @param existingKeyPair existing KeyPair object which is reused if required. If null, new KeyPair is allocated
   * @return new or existing object with fresh key pair value
   */
  KeyPair newKeyPair(KeyPair existingKeyPair) {
    ECPrivateKey privKey;
    ECPublicKey pubKey;
    if (existingKeyPair == null) { // Allocate if not supplied
      existingKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KEY_LENGTH);
    }

    // Some implementation wil not return valid pub key until ecKeyPair.genKeyPair() is called
    // Other implementation will fail with exception if same is called => try catch and drop any exception
    try {
      pubKey = (ECPublicKey) existingKeyPair.getPublic();
      if (pubKey == null) {
        existingKeyPair.genKeyPair();
      }
    } catch (Exception e) {
    } // intentionally do nothing

    privKey = (ECPrivateKey) existingKeyPair.getPrivate();
    pubKey = (ECPublicKey) existingKeyPair.getPublic();

    // Set required values
    privKey.setFieldFP(p, (short) 0, (short) p.length);
    privKey.setA(a, (short) 0, (short) a.length);
    privKey.setB(b, (short) 0, (short) b.length);
    privKey.setG(G, (short) 0, (short) G.length);
    privKey.setR(r, (short) 0, (short) r.length);
    privKey.setK((short) 1);

    pubKey.setFieldFP(p, (short) 0, (short) p.length);
    pubKey.setA(a, (short) 0, (short) a.length);
    pubKey.setB(b, (short) 0, (short) b.length);
    pubKey.setG(G, (short) 0, (short) G.length);
    pubKey.setR(r, (short) 0, (short) r.length);
    pubKey.setK((short) 1);

    existingKeyPair.genKeyPair();

    return existingKeyPair;
  }

  public KeyPair newKeyPair_legacy(KeyPair existingKeyPair) {
    ECPrivateKey privKey;
    ECPublicKey pubKey;
    if (existingKeyPair == null) {
      // We need to create required objects
      privKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_LENGTH, false);
      pubKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_LENGTH, false);
    }
    else {
      // Obtain from object
      privKey = (ECPrivateKey) existingKeyPair.getPrivate();
      pubKey = (ECPublicKey) existingKeyPair.getPublic();
    }
    // Set required values
    privKey.setFieldFP(p, (short) 0, (short) p.length);
    privKey.setA(a, (short) 0, (short) a.length);
    privKey.setB(b, (short) 0, (short) b.length);
    privKey.setG(G, (short) 0, (short) G.length);
    privKey.setR(r, (short) 0, (short) r.length);

    pubKey.setFieldFP(p, (short) 0, (short) p.length);
    pubKey.setA(a, (short) 0, (short) a.length);
    pubKey.setB(b, (short) 0, (short) b.length);
    pubKey.setG(G, (short) 0, (short) G.length);
    pubKey.setR(r, (short) 0, (short) r.length);

    if (existingKeyPair == null) { // Allocate if not supplied
      existingKeyPair = new KeyPair(pubKey, privKey);
    }
    existingKeyPair.genKeyPair();

    return existingKeyPair;
  }


  /**
   * Converts provided Bignat into temporary EC private key object. No new
   * allocation is performed, returned ECPrivateKey is overwritten by next call.
   * @param bn Bignat with new value
   * @return ECPrivateKey initialized with provided Bignat
   */
  public ECPrivateKey bignatAsPrivateKey(Bignat bn) {
    disposable_priv.setS(bn.as_byte_array(), (short) 0, bn.length());
    return disposable_priv;
  }

  /**
   * Set new G for this curve. Also updates all dependent key values.
   * @param newG buffer with new G
   * @param newGOffset start offset within newG
   * @param newGLen length of new G
   */
  public void setG(byte[] newG, short newGOffset, short newGLen) {
    Util.arrayCopyNonAtomic(newG, newGOffset, G, (short) 0, newGLen);
    this.disposable_pair = this.newKeyPair(this.disposable_pair);
    this.disposable_priv = (ECPrivateKey) this.disposable_pair.getPrivate();
    this.disposable_priv.setG(newG, newGOffset, newGLen);
  }
}
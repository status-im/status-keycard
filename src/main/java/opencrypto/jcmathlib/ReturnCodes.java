package opencrypto.jcmathlib;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ReturnCodes {
  // Custom error response codes
  public static final short SW_BIGNAT_RESIZETOLONGER          = (short) 0x7000;
  public static final short SW_BIGNAT_REALLOCATIONNOTALLOWED  = (short) 0x7001;
  public static final short SW_BIGNAT_MODULOTOOLARGE          = (short) 0x7002;
  public static final short SW_BIGNAT_INVALIDCOPYOTHER        = (short) 0x7003;
  public static final short SW_BIGNAT_INVALIDRESIZE           = (short) 0x7004;
  public static final short SW_LOCK_ALREADYLOCKED             = (short) 0x7005;
  public static final short SW_LOCK_NOTLOCKED                 = (short) 0x7006;
  public static final short SW_ECPOINT_INVALIDLENGTH          = (short) 0x700a;
  public static final short SW_ALLOCATOR_INVALIDOBJID         = (short) 0x700c;
}

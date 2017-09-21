package im.status.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class WalletApplet extends Applet {
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
  }

  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    register(bArray, (short) (bOffset + 1), bArray[0]);
  }

  public void process(APDU apdu) throws ISOException {
    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }
}

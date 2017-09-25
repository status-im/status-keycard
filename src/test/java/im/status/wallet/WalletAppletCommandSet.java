package im.status.wallet;

import javacard.framework.ISO7816;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class WalletAppletCommandSet {
  public static final String APPLET_AID = "53746174757357616C6C6574417070";
  public static final byte[] APPLET_AID_BYTES = Hex.decode(APPLET_AID);

  public static ResponseAPDU select(CardChannel apduChannel) throws CardException {
    CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, APPLET_AID_BYTES);
    return apduChannel.transmit(selectApplet);
  }
}

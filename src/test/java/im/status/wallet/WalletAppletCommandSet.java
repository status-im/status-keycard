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
  private final CardChannel apduChannel;
  private SecureChannelSession secureChannel;

  public WalletAppletCommandSet(CardChannel apduChannel) {
    this.apduChannel = apduChannel;
  }

  public void setSecureChannel(SecureChannelSession secureChannel) {
    this.secureChannel = secureChannel;
  }

  public ResponseAPDU select() throws CardException {
    CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, APPLET_AID_BYTES);
    return apduChannel.transmit(selectApplet);
  }

  public ResponseAPDU openSecureChannel() throws CardException {
    return secureChannel.openSecureChannel(apduChannel);
  }

  public ResponseAPDU verifyPIN(String pin) throws CardException {
    CommandAPDU verifyPIN = new CommandAPDU(0x80, WalletApplet.INS_VERIFY_PIN, 0, 0, secureChannel.encryptAPDU(pin.getBytes()));
    return apduChannel.transmit(verifyPIN);
  }
}

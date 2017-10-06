package im.status.wallet;

import javacard.framework.ISO7816;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.ECKeyPair;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.KeyPair;

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

  public ResponseAPDU changePIN(String pin) throws CardException {
    CommandAPDU changePIN = new CommandAPDU(0x80, WalletApplet.INS_CHANGE_PIN, 0, 0, secureChannel.encryptAPDU(pin.getBytes()));
    return apduChannel.transmit(changePIN);
  }

  public ResponseAPDU unblockPIN(String puk, String newPin) throws CardException {
    CommandAPDU unblockPIN = new CommandAPDU(0x80, WalletApplet.INS_UNBLOCK_PIN, 0, 0, secureChannel.encryptAPDU((puk + newPin).getBytes()));
    return apduChannel.transmit(unblockPIN);
  }

  public ResponseAPDU loadKey(KeyPair keyPair) throws CardException {
    byte[] publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
    byte[] privateKey = ((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray();

    int privLen = privateKey.length;
    int privOff = 0;

    if(privateKey[0] == 0x00) {
      privOff++;
      privLen--;
    }

    byte[] data = new byte[publicKey.length + privLen + 6];
    data[0] = (byte) 0xA1;
    data[1] = (byte) (publicKey.length + privLen + 4);
    data[2] = (byte) 0x80;
    data[3] = (byte) publicKey.length;
    System.arraycopy(publicKey, 0, data, 4, publicKey.length);
    data[4 + publicKey.length] = (byte) 0x81;
    data[5 + publicKey.length] = (byte) privLen;
    System.arraycopy(privateKey, privOff, data, 6 + publicKey.length, privLen);

    return loadKey(data, WalletApplet.LOAD_KEY_P1_EC);
  }

  public ResponseAPDU loadKey(ECKeyPair ecKeyPair) throws CardException {
    byte[] publicKey = ecKeyPair.getPublicKey().toByteArray();
    byte[] privateKey = ecKeyPair.getPrivateKey().toByteArray();

    int privLen = privateKey.length;
    int privOff = 0;

    int pubLen = publicKey.length;
    int pubOff = 0;

    if(privateKey[0] == 0x00) {
      privOff++;
      privLen--;
    }

    if(publicKey[0] == 0x00) {
      pubOff++;
      pubLen--;
    }

    byte[] data = new byte[pubLen + privLen + 7];
    data[0] = (byte) 0xA1;
    data[1] = (byte) (pubLen + privLen + 5);
    data[2] = (byte) 0x80;
    data[3] = (byte) (pubLen + 1);
    data[4] = (byte) 0x04;
    System.arraycopy(publicKey, pubOff, data, 5, pubLen);
    data[5 + pubLen] = (byte) 0x81;
    data[6 + pubLen] = (byte) privLen;
    System.arraycopy(privateKey, privOff, data, 7 + pubLen, privLen);

    return loadKey(data, WalletApplet.LOAD_KEY_P1_EC);
  }

  public ResponseAPDU loadKey(byte[] data, byte keyType) throws CardException {
    CommandAPDU loadKey = new CommandAPDU(0x80, WalletApplet.INS_LOAD_KEY, keyType, 0, secureChannel.encryptAPDU(data));
    return apduChannel.transmit(loadKey);
  }

  public ResponseAPDU sign(byte[] data, byte dataType, boolean isFirst, boolean isLast) throws CardException {
    byte p2 = (byte) ((isFirst ? 0x01 : 0x00) | (isLast ? 0x80 : 0x00));
    CommandAPDU sign = new CommandAPDU(0x80, WalletApplet.INS_SIGN, dataType, p2, secureChannel.encryptAPDU(data));
    return apduChannel.transmit(sign);
  }
}

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
import java.security.PrivateKey;

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

  public ResponseAPDU getStatus(byte info) throws CardException {
    CommandAPDU getStatus = new CommandAPDU(0x80, WalletApplet.INS_GET_STATUS, info, 0, 256);
    return apduChannel.transmit(getStatus);
  }

  public boolean getPublicKeyDerivationSupport() throws CardException {
    ResponseAPDU resp = getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    byte[] data = secureChannel.decryptAPDU(resp.getData());
    return data[data.length - 1] == 1;
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

  public ResponseAPDU loadKey(PrivateKey aPrivate, byte[] chainCode) throws CardException {
    byte[] privateKey = ((ECPrivateKey) aPrivate).getD().toByteArray();

    int privLen = privateKey.length;
    int privOff = 0;

    if(privateKey[0] == 0x00) {
      privOff++;
      privLen--;
    }

    byte[] data = new byte[chainCode.length + privLen];
    System.arraycopy(privateKey, privOff, data, 0, privLen);
    System.arraycopy(chainCode, 0, data, privLen, chainCode.length);

    return loadKey(data, WalletApplet.LOAD_KEY_P1_SEED);
  }

  public ResponseAPDU loadKey(KeyPair ecKeyPair) throws CardException {
    return loadKey(ecKeyPair, false, null);
  }

  public ResponseAPDU loadKey(KeyPair keyPair, boolean omitPublicKey, byte[] chainCode) throws CardException {
    byte[] publicKey = omitPublicKey ? null : ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
    byte[] privateKey = ((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray();

    return loadKey(publicKey, privateKey, chainCode);
  }

  public ResponseAPDU loadKey(ECKeyPair ecKeyPair) throws CardException {
    byte[] publicKey = ecKeyPair.getPublicKey().toByteArray();
    byte[] privateKey = ecKeyPair.getPrivateKey().toByteArray();

    int pubLen = publicKey.length;
    int pubOff = 0;

    if(publicKey[0] == 0x00) {
      pubOff++;
      pubLen--;
    }

    byte[] ansiPublic = new byte[pubLen + 1];
    ansiPublic[0] = 0x04;
    System.arraycopy(publicKey, pubOff, ansiPublic, 1, pubLen);

    return loadKey(ansiPublic, privateKey, null);
  }

  public ResponseAPDU loadKey(byte[] publicKey, byte[] privateKey, byte[] chainCode) throws CardException {
    int privLen = privateKey.length;
    int privOff = 0;

    if(privateKey[0] == 0x00) {
      privOff++;
      privLen--;
    }

    int off = 0;
    int totalLength = publicKey == null ? 0 : (publicKey.length + 2);
    totalLength += (privLen + 2);
    totalLength += chainCode == null ? 0 : (chainCode.length + 2);

    if (totalLength > 127) {
      totalLength += 3;
    } else {
      totalLength += 2;
    }

    byte[] data = new byte[totalLength];
    data[off++] = (byte) 0xA1;

    if (totalLength > 127) {
      data[off++] = (byte) 0x81;
      data[off++] = (byte) (totalLength - 3);
    } else {
      data[off++] = (byte) (totalLength - 2);
    }

    if (publicKey != null) {
      data[off++] = WalletApplet.TLV_PUB_KEY;
      data[off++] = (byte) publicKey.length;
      System.arraycopy(publicKey, 0, data, off, publicKey.length);
      off += publicKey.length;
    }

    data[off++] = WalletApplet.TLV_PRIV_KEY;
    data[off++] = (byte) privLen;
    System.arraycopy(privateKey, privOff, data, off, privLen);
    off += privLen;

    byte p1;

    if (chainCode != null) {
      p1 = WalletApplet.LOAD_KEY_P1_EXT_EC;
      data[off++] = (byte) WalletApplet.TLV_CHAIN_CODE;
      data[off++] = (byte) chainCode.length;
      System.arraycopy(chainCode, 0, data, off, chainCode.length);
    } else {
      p1 = WalletApplet.LOAD_KEY_P1_EC;
    }

    return loadKey(data, p1);
  }

  public ResponseAPDU loadKey(byte[] data, byte keyType) throws CardException {
    CommandAPDU loadKey = new CommandAPDU(0x80, WalletApplet.INS_LOAD_KEY, keyType, 0, secureChannel.encryptAPDU(data));
    return apduChannel.transmit(loadKey);
  }

  public ResponseAPDU generateMnemonic(int cs) throws CardException {
    CommandAPDU generateMnemonic = new CommandAPDU(0x80, WalletApplet.INS_GENERATE_MNEMONIC, cs, 0, 256);
    return apduChannel.transmit(generateMnemonic);
  }

  public ResponseAPDU sign(byte[] data, byte dataType, boolean isFirst, boolean isLast) throws CardException {
    byte p2 = (byte) ((isFirst ? 0x01 : 0x00) | (isLast ? 0x80 : 0x00));
    CommandAPDU sign = new CommandAPDU(0x80, WalletApplet.INS_SIGN, dataType, p2, secureChannel.encryptAPDU(data));
    return apduChannel.transmit(sign);
  }

  public ResponseAPDU deriveKey(byte[] data) throws CardException {
    return deriveKey(data, true, false, false);
  }

  public ResponseAPDU deriveKey(byte[] data, boolean reset, boolean assisted, boolean isPublicKey) throws CardException {
    byte p1 = assisted ? WalletApplet.DERIVE_P1_ASSISTED_MASK : 0;
    p1 |= reset ? 0 : WalletApplet.DERIVE_P1_APPEND_MASK;
    byte p2 = isPublicKey ? WalletApplet.DERIVE_P2_PUBLIC_KEY : WalletApplet.DERIVE_P2_KEY_PATH;

    CommandAPDU deriveKey = new CommandAPDU(0x80, WalletApplet.INS_DERIVE_KEY, p1, p2, secureChannel.encryptAPDU(data));
    return apduChannel.transmit(deriveKey);
  }

  public ResponseAPDU setPinlessPath(byte [] data) throws CardException {
    CommandAPDU setPinlessPath = new CommandAPDU(0x80, WalletApplet.INS_SET_PINLESS_PATH, 0x00, 0x00, secureChannel.encryptAPDU(data));
    return apduChannel.transmit(setPinlessPath);
  }

  public ResponseAPDU exportKey(byte keyPathIndex) throws CardException {
    CommandAPDU exportKey = new CommandAPDU(0x80, WalletApplet.INS_EXPORT_KEY, keyPathIndex, 0x00, 256);
    return apduChannel.transmit(exportKey);
  }
}

package im.status.wallet;

import com.licel.jcardsim.utils.ByteUtil;
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
import java.util.Arrays;

/**
 * This class is used to send APDU to the applet. Each method corresponds to an APDU as defined in the APPLICATION.md
 * file. Some APDUs map to multiple methods for the sake of convenience since their payload or response require some
 * pre/post processing.
 */
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

  /**
   * Selects the applet. The applet is assumed to have been installed with its default AID. The returned data is a
   * public key which must be used to initialize the secure channel.
   *
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU select() throws CardException {
    if (secureChannel != null) {
      secureChannel.reset();
    }

    CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, APPLET_AID_BYTES);
    return apduChannel.transmit(selectApplet);
  }

  /**
   * Opens the secure channel. Calls the corresponding method of the SecureChannel class.
   *
   * @return the raw card response
   * @throws CardException communication error
   */
  public void autoOpenSecureChannel() throws CardException {
    secureChannel.autoOpenSecureChannel(apduChannel);
  }

  /**
   * Automatically pairs. Calls the corresponding method of the SecureChannel class.
   *
   * @throws CardException communication error
   */
  public void autoPair(byte[] sharedSecret) throws CardException {
    secureChannel.autoPair(apduChannel, sharedSecret);
  }

  /**
   * Automatically unpairs. Calls the corresponding method of the SecureChannel class.
   *
   * @throws CardException communication error
   */
  public void autoUnpair() throws CardException {
    secureChannel.autoUnpair(apduChannel);
  }

  /**
   * Sends a OPEN SECURE CHANNEL APDU. Calls the corresponding method of the SecureChannel class.
   */
  public ResponseAPDU openSecureChannel(byte index, byte[] data) throws CardException {
    return secureChannel.openSecureChannel(apduChannel, index, data);
  }

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU. Calls the corresponding method of the SecureChannel class.
   */
  public ResponseAPDU mutuallyAuthenticate() throws CardException {
    return secureChannel.mutuallyAuthenticate(apduChannel);
  }

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU. Calls the corresponding method of the SecureChannel class.
   */
  public ResponseAPDU mutuallyAuthenticate(byte[] data) throws CardException {
    return secureChannel.mutuallyAuthenticate(apduChannel, data);
  }

  /**
   * Sends a PAIR APDU. Calls the corresponding method of the SecureChannel class.
   */
  public ResponseAPDU pair(byte p1, byte[] data) throws CardException {
    return secureChannel.pair(apduChannel, p1, data);
  }

  /**
   * Sends a UNPAIR APDU. Calls the corresponding method of the SecureChannel class.
   */
  public ResponseAPDU unpair(byte p1) throws CardException {
    return secureChannel.unpair(apduChannel, p1);
  }

  /**
   * Sends a GET STATUS APDU. The info byte is the P1 parameter of the command, valid constants are defined in the applet
   * class itself.
   *
   * @param info the P1 of the APDU
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU getStatus(byte info) throws CardException {
    CommandAPDU getStatus = secureChannel.protectedCommand(0x80, WalletApplet.INS_GET_STATUS, info, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, getStatus);
  }

  /**
   * Sends a GET STATUS APDU to retrieve the APPLICATION STATUS template and reads the byte indicating public key
   * derivation support.
   *
   * @return whether public key derivation is supported or not
   * @throws CardException communication error
   */
  public boolean getPublicKeyDerivationSupport() throws CardException {
    ResponseAPDU resp = getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    byte[] data = resp.getData();
    return data[data.length - 1] != 0x00;
  }

  /**
   * Sends a GET STATUS APDU to retrieve the APPLICATION STATUS template and reads the byte indicating key initialization
   * status
   *
   * @return whether public key derivation is supported or not
   * @throws CardException communication error
   */
  public boolean getKeyInitializationStatus() throws CardException {
    ResponseAPDU resp = getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    byte[] data = resp.getData();
    return data[data.length - 4] != 0x00;
  }

  /**
   * Sends a VERIFY PIN APDU. The raw bytes of the given string are encrypted using the secure channel and used as APDU
   * data.
   *
   * @param pin the pin
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU verifyPIN(String pin) throws CardException {
    CommandAPDU verifyPIN = secureChannel.protectedCommand(0x80, WalletApplet.INS_VERIFY_PIN, 0, 0, pin.getBytes());
    return secureChannel.transmit(apduChannel, verifyPIN);
  }

  /**
   * Sends a CHANGE PIN APDU. The raw bytes of the given string are encrypted using the secure channel and used as APDU
   * data.
   *
   * @param pin the new PIN
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU changePIN(String pin) throws CardException {
    CommandAPDU changePIN = secureChannel.protectedCommand(0x80, WalletApplet.INS_CHANGE_PIN, 0, 0, pin.getBytes());
    return secureChannel.transmit(apduChannel, changePIN);
  }

  /**
   * Sends an UNBLOCK PIN APDU. The PUK and PIN are concatenated and the raw bytes are encrypted using the secure
   * channel and used as APDU data.
   *
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU unblockPIN(String puk, String newPin) throws CardException {
    CommandAPDU unblockPIN = secureChannel.protectedCommand(0x80, WalletApplet.INS_UNBLOCK_PIN, 0, 0, (puk + newPin).getBytes());
    return secureChannel.transmit(apduChannel, unblockPIN);
  }

  /**
   * Sends a LOAD KEY APDU. The given private key and chain code are formatted as a raw binary seed and the P1 of
   * the command is set to WalletApplet.LOAD_KEY_P1_SEED (0x03). This works on cards which support public key derivation.
   * The loaded keyset is extended and support further key derivation.
   *
   * @param aPrivate a private key
   * @param chainCode the chain code
   * @return the raw card response
   * @throws CardException communication error
   */
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

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format, includes the public key and no chain code, meaning that
   * the card will not be able to do further key derivation.
   *
   * @param ecKeyPair a key pair
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU loadKey(KeyPair ecKeyPair) throws CardException {
    return loadKey(ecKeyPair, false, null);
  }

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format. The public key is included or not depending on the value
   * of the omitPublicKey parameter. The chain code is included if the chainCode is not null. P1 is set automatically
   * to either WalletApplet.LOAD_KEY_P1_EC or WalletApplet.LOAD_KEY_P1_EXT_EC depending on the presence of the chainCode.
   *
   * @param keyPair a key pair
   * @param omitPublicKey whether the public key is sent or not
   * @param chainCode the chain code
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU loadKey(KeyPair keyPair, boolean omitPublicKey, byte[] chainCode) throws CardException {
    byte[] publicKey = omitPublicKey ? null : ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
    byte[] privateKey = ((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray();

    return loadKey(publicKey, privateKey, chainCode);
  }

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format, includes the public key and no chain code, meaning that
   * the card will not be able to do further key derivation. This is needed when the argument is an EC keypair from
   * the web3j package instead of the regular Java ones. Used by the test which actually submits the transaction to
   * the network.
   *
   * @param ecKeyPair a key pair
   * @return the raw card response
   * @throws CardException communication error
   */
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

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format. The public key is included if not null. The chain code is
   * included if not null. P1 is set automatically to either WalletApplet.LOAD_KEY_P1_EC or
   * WalletApplet.LOAD_KEY_P1_EXT_EC depending on the presence of the chainCode.
   *
   * @param publicKey a raw public key
   * @param privateKey a raw private key
   * @param chainCode the chain code
   * @return the raw card response
   * @throws CardException communication error
   */
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

  /**
   * Sends a LOAD KEY APDU. The data is encrypted and sent as-is. The keyType parameter is used as P1.
   *
   * @param data key data
   * @param keyType the P1 parameter
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU loadKey(byte[] data, byte keyType) throws CardException {
    CommandAPDU loadKey = secureChannel.protectedCommand(0x80, WalletApplet.INS_LOAD_KEY, keyType, 0, data);
    return secureChannel.transmit(apduChannel, loadKey);
  }

  /**
   * Sends a GENERATE MNEMONIC APDU. The cs parameter is the length of the checksum and is used as P1.
   *
   * @param cs the P1 parameter
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU generateMnemonic(int cs) throws CardException {
    CommandAPDU generateMnemonic = secureChannel.protectedCommand(0x80, WalletApplet.INS_GENERATE_MNEMONIC, cs, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, generateMnemonic);
  }

  /**
   * Sends a REMOVE KEY APDU.
   *
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU removeKey() throws CardException {
    CommandAPDU removeKey = secureChannel.protectedCommand(0x80, WalletApplet.INS_REMOVE_KEY, 0, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, removeKey);
  }

  /**
   * Sends a SIGN APDU. The dataType is P1 as defined in the applet. The isFirst and isLast arguments are used to form
   * the P2 parameter. The data is the data to sign, or part of it. Only when sending the last block a signature is
   * generated and thus returned. When signing a precomputed hash it must be done in a single block, so isFirst and
   * isLast will always be true at the same time.
   *
   * @param data the data to sign
   * @param dataType the P1 parameter
   * @param isFirst whether this is the first block of the command or not
   * @param isLast whether this is the last block of the command or not
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU sign(byte[] data, byte dataType, boolean isFirst, boolean isLast) throws CardException {
    byte p2 = (byte) ((isFirst ? 0x01 : 0x00) | (isLast ? 0x80 : 0x00));
    CommandAPDU sign = secureChannel.protectedCommand(0x80, WalletApplet.INS_SIGN, dataType, p2, data);
    return secureChannel.transmit(apduChannel, sign);
  }

  /**
   * Sends a DERIVE KEY APDU. The data is encrypted and sent as-is. The P1 and P2 parameters are forced to 0, meaning
   * that the derivation starts from the master key and is non-assisted.
   *
   * @param data the raw key path
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU deriveKey(byte[] data) throws CardException {
    return deriveKey(data, WalletApplet.DERIVE_P1_SOURCE_MASTER, false, false);
  }

  /**
   * Sends a DERIVE KEY APDU. The data is encrypted and sent as-is. The reset and assisted parameters are combined to
   * form P1. The isPublicKey parameter is used for P2.
   *
   * @param data the raw key path or a public key
   * @param source the source to start derivation
   * @param assisted whether we are doing assisted derivation or not
   * @param isPublicKey whether we are sending a public key or a key path (only make sense during assisted derivation)
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU deriveKey(byte[] data, int source, boolean assisted, boolean isPublicKey) throws CardException {
    byte p1 = assisted ? WalletApplet.DERIVE_P1_ASSISTED_MASK : 0;
    p1 |= source;
    byte p2 = isPublicKey ? WalletApplet.DERIVE_P2_PUBLIC_KEY : WalletApplet.DERIVE_P2_KEY_PATH;

    CommandAPDU deriveKey = secureChannel.protectedCommand(0x80, WalletApplet.INS_DERIVE_KEY, p1, p2, data);
    return secureChannel.transmit(apduChannel, deriveKey);
  }

  /**
   * Sends a SET PINLESS PATH APDU. The data is encrypted and sent as-is.
   *
   * @param data the raw key path
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU setPinlessPath(byte [] data) throws CardException {
    CommandAPDU setPinlessPath = secureChannel.protectedCommand(0x80, WalletApplet.INS_SET_PINLESS_PATH, 0x00, 0x00, data);
    return secureChannel.transmit(apduChannel, setPinlessPath);
  }

  /**
   * Sends an EXPORT KEY APDU. The keyPathIndex is used as P1. Valid values are defined in the applet itself
   *
   * @param keyPathIndex the P1 parameter
   * @param publicOnly the P2 parameter
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU exportKey(byte keyPathIndex, boolean publicOnly) throws CardException {
    byte p2 = publicOnly ? WalletApplet.EXPORT_KEY_P2_PUBLIC_ONLY : WalletApplet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC;
    CommandAPDU exportKey = secureChannel.protectedCommand(0x80, WalletApplet.INS_EXPORT_KEY, keyPathIndex, p2, new byte[0]);
    return secureChannel.transmit(apduChannel, exportKey);
  }

  /**
   * Sends the INIT command to the card.
   *
   * @param pin the PIN
   * @param puk the PUK
   * @param sharedSecret the shared secret for pairing
   * @return the raw card response
   * @throws CardException communication error
   */
  public ResponseAPDU init(String pin, String puk, byte[] sharedSecret) throws CardException {
    byte[] initData = Arrays.copyOf(pin.getBytes(), pin.length() + puk.length() + sharedSecret.length);
    System.arraycopy(puk.getBytes(), 0, initData, pin.length(), puk.length());
    System.arraycopy(sharedSecret, 0, initData, pin.length() + puk.length(), sharedSecret.length);
    CommandAPDU init = new CommandAPDU(0x80, WalletApplet.INS_INIT, 0, 0, secureChannel.oneShotEncrypt(initData));
    return apduChannel.transmit(init);
  }
}

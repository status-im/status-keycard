package im.status.wallet;

import im.status.hardwallet.lite.WalletAppletCommandSet;
import org.web3j.crypto.ECKeyPair;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

public class TestWalletAppletCommandSet extends WalletAppletCommandSet {
  public TestWalletAppletCommandSet(CardChannel apduChannel) {
    super(apduChannel);
  }

  public void setSecureChannel(TestSecureChannelSession secureChannel) {
    super.setSecureChannel(secureChannel);
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
}


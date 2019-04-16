package im.status.keycard;

import im.status.keycard.applet.ApplicationStatus;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import org.web3j.crypto.ECKeyPair;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;


public class TestKeycardCommandSet extends KeycardCommandSet {
  public TestKeycardCommandSet(CardChannel apduChannel) {
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
   * @throws IOException communication error
   */
  public APDUResponse loadKey(ECKeyPair ecKeyPair) throws IOException {
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
   * Sends a LOAD KEY APDU. The given private key and chain code are formatted as a raw binary seed and the P1 of
   * the command is set to LOAD_KEY_P1_SEED (0x03). This works on cards which support public key derivation.
   * The loaded keyset is extended and support further key derivation.
   *
   * @param aPrivate a private key
   * @param chainCode the chain code
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse loadKey(PrivateKey aPrivate, byte[] chainCode) throws IOException {
    byte[] privateKey = ((ECPrivateKey) aPrivate).getS().toByteArray();

    int privLen = privateKey.length;
    int privOff = 0;

    if(privateKey[0] == 0x00) {
      privOff++;
      privLen--;
    }

    byte[] data = new byte[chainCode.length + privLen];
    System.arraycopy(privateKey, privOff, data, 0, privLen);
    System.arraycopy(chainCode, 0, data, privLen, chainCode.length);

    return loadKey(data, LOAD_KEY_P1_SEED);
  }

  /**
   * Sends a GET STATUS APDU to retrieve the APPLICATION STATUS template and reads the byte indicating key initialization
   * status
   *
   * @return whether the master key is present or not
   * @throws IOException communication error
   */
  public boolean getKeyInitializationStatus() throws IOException {
    APDUResponse resp = getStatus(GET_STATUS_P1_APPLICATION);
    return new ApplicationStatus(resp.getData()).hasMasterKey();
  }

  public APDUResponse foo() throws IOException {
    return this.exportCerts();
  }
}


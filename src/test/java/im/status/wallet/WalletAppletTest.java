package im.status.wallet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.RawTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import javax.smartcardio.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Random;

import static org.apache.commons.codec.digest.DigestUtils.sha256;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Test the Wallet Applet")
public class WalletAppletTest {
  // Psiring key is WalletAppletTest
  public static final byte[] SHARED_SECRET = new byte[] { (byte) 0xe9, (byte) 0x29, (byte) 0xd4, (byte) 0x25, (byte) 0xd7, (byte) 0xf7, (byte) 0x3c, (byte) 0x2a, (byte) 0x0a, (byte) 0x24, (byte) 0xff, (byte) 0xef, (byte) 0xad, (byte) 0x87, (byte) 0xb6, (byte) 0x5e, (byte) 0x9b, (byte) 0x2e, (byte) 0xe9, (byte) 0x66, (byte) 0x03, (byte) 0xea, (byte) 0xb3, (byte) 0x4d, (byte) 0x64, (byte) 0x08, (byte) 0x8b, (byte) 0x5a, (byte) 0xae, (byte) 0x2a, (byte) 0x02, (byte) 0x6f };
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;
  private static CardSimulator simulator;

  private SecureChannelSession secureChannel;
  private WalletAppletCommandSet cmdSet;

  private static final boolean USE_SIMULATOR;

  static {
    USE_SIMULATOR = !System.getProperty("im.status.wallet.test.simulated", "false").equals("false");
  }

  @BeforeAll
  static void initAll() throws CardException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    if (USE_SIMULATOR) {
      simulator = new CardSimulator();
      AID appletAID = AIDUtil.create(WalletAppletCommandSet.APPLET_AID);
      byte[] instParams = Hex.decode("0F53746174757357616C6C657441707001000C313233343536373839303132");
      simulator.installApplet(appletAID, WalletApplet.class, instParams, (short) 0, (byte) instParams.length);
      cardTerminal = CardTerminalSimulator.terminal(simulator);
    } else {
      TerminalFactory tf = TerminalFactory.getDefault();

      for (CardTerminal t : tf.terminals().list()) {
        if (t.isCardPresent()) {
          cardTerminal = t;
          break;
        }
      }
    }

    Card apduCard = cardTerminal.connect("*");
    apduChannel = apduCard.getBasicChannel();
  }

  @BeforeEach
  void init() throws CardException {
    reset();
    cmdSet = new WalletAppletCommandSet(apduChannel);
    byte[] keyData = extractPublicKeyFromSelect(cmdSet.select().getData());
    secureChannel = new SecureChannelSession(keyData);
    cmdSet.setSecureChannel(secureChannel);
    cmdSet.autoPair(SHARED_SECRET);
  }

  @AfterEach
  void tearDown() throws CardException {
    resetAndSelectAndOpenSC();
    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    cmdSet.autoUnpair();
  }

  @AfterAll
  static void tearDownAll() {
  }

  @Test
  @DisplayName("SELECT command")
  void selectTest() throws CardException {
    ResponseAPDU response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
    byte[] data = response.getData();
    assertEquals(WalletApplet.TLV_APPLICATION_INFO_TEMPLATE, data[0]);
    assertEquals(WalletApplet.TLV_UID, data[2]);
    assertEquals(WalletApplet.TLV_PUB_KEY, data[20]);
    assertEquals(WalletApplet.TLV_INT, data[22 + data[21]]);
    assertEquals(WalletApplet.APPLICATION_VERSION >> 8, data[24 + data[21]]);
    assertEquals(WalletApplet.APPLICATION_VERSION & 0xFF, data[25 + data[21]]);
    assertEquals(WalletApplet.TLV_INT, data[26 + data[21]]);
    assertEquals(WalletApplet.TLV_KEY_UID, data[29 + data[21]]);
  }

  @Test
  @DisplayName("OPEN SECURE CHANNEL command")
  void openSecureChannelTest() throws CardException {
    // Wrong P1
    ResponseAPDU response = cmdSet.openSecureChannel((byte)(secureChannel.getPairingIndex() + 1), new byte[65]);
    assertEquals(0x6A86, response.getSW());

    // Wrong data
    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), new byte[65]);
    assertEquals(0x6A80, response.getSW());

    // Good case
    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSW());
    assertEquals(SecureChannel.SC_SECRET_LENGTH + SecureChannel.SC_BLOCK_SIZE, response.getData().length);
    secureChannel.processOpenSecureChannelResponse(response);

    // Send command before MUTUALLY AUTHENTICATE
    secureChannel.reset();
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x6985, response.getSW());

    // Perform mutual authentication
    secureChannel.setOpen();
    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x9000, response.getSW());
    assertTrue(secureChannel.verifyMutuallyAuthenticateResponse(response));

    // Verify that the channel is open
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("MUTUALLY AUTHENTICATE command")
  void mutuallyAuthenticateTest() throws CardException {
    // Mutual authentication before opening a Secure Channel
    ResponseAPDU response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSW());

    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSW());
    secureChannel.processOpenSecureChannelResponse(response);

    // Wrong data format
    response = cmdSet.mutuallyAuthenticate(new byte[31]);
    assertEquals(0x6982, response.getSW());

    // Verify that after wrong authentication, the command does not work
    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSW());

    // Wrong authentication data
    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSW());
    secureChannel.processOpenSecureChannelResponse(response);
    response = apduChannel.transmit(new CommandAPDU(0x80, SecureChannel.INS_MUTUALLY_AUTHENTICATE, 0, 0, new byte[48]));
    assertEquals(0x6982, response.getSW());
    secureChannel.reset();
    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSW());

    // Good case
    cmdSet.autoOpenSecureChannel();

    // MUTUALLY AUTHENTICATE has no effect on an already open secure channel
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());

    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSW());

    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("PAIR command")
  void pairTest() throws CardException {
    // Wrong data length
    ResponseAPDU response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, new byte[31]);
    assertEquals(0x6A80, response.getSW());

    // Wrong P1
    response = cmdSet.pair(SecureChannel.PAIR_P1_LAST_STEP, new byte[32]);
    assertEquals(0x6A86, response.getSW());

    // Wrong client cryptogram
    byte[] challenge = new byte[32];
    Random random = new Random();
    random.nextBytes(challenge);
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.pair(SecureChannel.PAIR_P1_LAST_STEP, challenge);
    assertEquals(0x6982, response.getSW());

    // Interrupt session
    random.nextBytes(challenge);
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertEquals(0x9000, response.getSW());
    cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    response = cmdSet.pair(SecureChannel.PAIR_P1_LAST_STEP, challenge);
    assertEquals(0x6A86, response.getSW());

    // Open secure channel
    cmdSet.autoOpenSecureChannel();
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertEquals(0x6985, response.getSW());
    cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());


    // Pair multiple indexes
    for (int i = 1; i < 5; i++) {
      cmdSet.autoPair(SHARED_SECRET);
      assertEquals(i, secureChannel.getPairingIndex());
      cmdSet.autoOpenSecureChannel();
      cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    }

    // Too many paired indexes
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertEquals(0x6A84, response.getSW());

    // Unpair all (except the last, which will be unpaired in the tearDown phase)
    cmdSet.autoOpenSecureChannel();
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    for (byte i = 0; i < 4; i++) {
      response = cmdSet.unpair(i);
      assertEquals(0x9000, response.getSW());
    }
  }

  @Test
  @DisplayName("UNPAIR command")
  void unpairTest() throws CardException {
    // Add a spare keyset
    byte sparePairingIndex = secureChannel.getPairingIndex();
    cmdSet.autoPair(SHARED_SECRET);

    // Proof that the old keyset is still usable
    ResponseAPDU response = cmdSet.openSecureChannel(sparePairingIndex, secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSW());

    // Security condition violation: SecureChannel not open
    response = cmdSet.unpair(sparePairingIndex);
    assertEquals(0x6985, response.getSW());

    // Not authenticated
    cmdSet.autoOpenSecureChannel();
    response = cmdSet.unpair(sparePairingIndex);
    assertEquals(0x6985, response.getSW());

    // Wrong P1
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.unpair((byte) 5);
    assertEquals(0x6A86, response.getSW());

    // Unpair spare keyset
    response = cmdSet.unpair(sparePairingIndex);
    assertEquals(0x9000, response.getSW());

    // Proof that unpaired is not usable
    response = cmdSet.openSecureChannel(sparePairingIndex, secureChannel.getPublicKey());
    assertEquals(0x6A86, response.getSW());
  }

  @Test
  @DisplayName("GET STATUS command")
  void getStatusTest() throws CardException {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x6985, response.getSW());
    cmdSet.autoOpenSecureChannel();

    // Good case. Since the order of test execution is undefined, the test cannot know if the keys are initialized or not.
    // Additionally, support for public key derivation is hw dependent.
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());
    byte[] data = response.getData();
    assertTrue(Hex.toHexString(data).matches("a30c0201030201050101[0f][0f]0101[0f][0f]"));

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());
    data = response.getData();
    assertTrue(Hex.toHexString(data).matches("a30c0201020201050101[0f][0f]0101[0f][0f]"));

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());
    data = response.getData();
    assertTrue(Hex.toHexString(data).matches("a30c0201030201050101[0f][0f]0101[0f][0f]"));

    // Check that key path is empty
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x9000, response.getSW());
    data = response.getData();
    assertEquals(0, data.length);
  }

  @Test
  @DisplayName("VERIFY PIN command")
  void verifyPinTest() throws CardException {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Wrong PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());

    // Correct PIN
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Check max retry counter
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSW());

    // Unblock PIN to make further tests possible
    response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("CHANGE PIN command")
  void changePinTest() throws CardException {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.changePIN("123456");
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN n ot verified
    response = cmdSet.changePIN("123456");
    assertEquals(0x6985, response.getSW());

    // Change PIN correctly, check that after PIN change the PIN remains validated
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN("123456");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN("654321");
    assertEquals(0x9000, response.getSW());

    // Reset card and verify that the new PIN has really been set
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSW());

    // Test wrong PIN formats (non-digits, too short, too long)
    response = cmdSet.changePIN("654a21");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN("54321");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN("7654321");
    assertEquals(0x6A80, response.getSW());

    // Reset the PIN to make further tests possible
    response = cmdSet.changePIN("000000");
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("UNBLOCK PIN command")
  void unblockPinTest() throws CardException {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Condition violation: PIN is not blocked
    response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x6985, response.getSW());

    // Block the PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSW());

    // Wrong PUK formats (too short, too long)
    response = cmdSet.unblockPIN("12345678901", "000000");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.unblockPIN("1234567890123", "000000");
    assertEquals(0x6A80, response.getSW());

    // Wrong PUK
    response = cmdSet.unblockPIN("123456789010", "000000");
    assertEquals(0x63C4, response.getSW());

    // Correct PUK
    response = cmdSet.unblockPIN("123456789012", "654321");
    assertEquals(0x9000, response.getSW());

    // Check that PIN has been changed and unblocked
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSW());

    // Reset the PIN to make further tests possible
    response = cmdSet.changePIN("000000");
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("LOAD KEY command")
  void loadKeyTest() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.loadKey(keyPair);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    int publicKeyDerivationSW = cmdSet.getPublicKeyDerivationSupport() ? 0x9000 : 0x6a81;

    // Security condition violation: PIN not verified
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Wrong key type
    response = cmdSet.loadKey(new byte[] { (byte) 0xAA, 0x02, (byte) 0x80, 0x00}, (byte) 0x00);
    assertEquals(0x6A86, response.getSW());

    // Wrong data (wrong template, missing private key, invalid keys)
    response = cmdSet.loadKey(new byte[]{(byte) 0xAA, 0x02, (byte) 0x80, 0x00}, WalletApplet.LOAD_KEY_P1_EC);
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.loadKey(new byte[]{(byte) 0xA1, 0x02, (byte) 0x80, 0x00}, WalletApplet.LOAD_KEY_P1_EC);
    assertEquals(0x6A80, response.getSW());

    if (!USE_SIMULATOR) { // the simulator does not check the key format
      response = cmdSet.loadKey(new byte[]{(byte) 0xA1, 0x06, (byte) 0x80, 0x01, 0x01, (byte) 0x81, 0x01, 0x02}, WalletApplet.LOAD_KEY_P1_EC);
      assertEquals(0x6A80, response.getSW());
    }

    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    // Correct LOAD KEY
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    keyPair = g.generateKeyPair();

    // Check extended key
    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSW());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    // Check omitted public key
    response = cmdSet.loadKey(keyPair, true, null);
    assertEquals(publicKeyDerivationSW, response.getSW());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));
    response = cmdSet.loadKey(keyPair, true, chainCode);
    assertEquals(publicKeyDerivationSW, response.getSW());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    // Check seed load
    response = cmdSet.loadKey(keyPair.getPrivate(), chainCode);
    assertEquals(publicKeyDerivationSW, response.getSW());
  }

  @Test
  @DisplayName("GENERATE MNEMONIC command")
  void generateMnemonicTest() throws Exception {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.generateMnemonic(4);
    assertEquals(0x6985, response.getSW());
    cmdSet.autoOpenSecureChannel();

    // Wrong P1 (too short, too long)
    response = cmdSet.generateMnemonic(3);
    assertEquals(0x6A86, response.getSW());

    response = cmdSet.generateMnemonic(9);
    assertEquals(0x6A86, response.getSW());

    // Good cases
    response = cmdSet.generateMnemonic(4);
    assertEquals(0x9000, response.getSW());
    assertMnemonic(12, response.getData());

    response = cmdSet.generateMnemonic(5);
    assertEquals(0x9000, response.getSW());
    assertMnemonic(15, response.getData());

    response = cmdSet.generateMnemonic(6);
    assertEquals(0x9000, response.getSW());
    assertMnemonic(18, response.getData());

    response = cmdSet.generateMnemonic(7);
    assertEquals(0x9000, response.getSW());
    assertMnemonic(21, response.getData());

    response = cmdSet.generateMnemonic(8);
    assertEquals(0x9000, response.getSW());
    assertMnemonic(24, response.getData());
  }

  @Test
  @DisplayName("REMOVE KEY command")
  void removeKeyTest() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.removeKey();
    assertEquals(0x6985, response.getSW());
    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.removeKey();
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
    byte[] data = response.getData();
    assertEquals(32, data[30 + data[21]]);
    verifyKeyUID(Arrays.copyOfRange(data, (31 + data[21]), (63 + data[21])), (ECPublicKey) keyPair.getPublic());

    cmdSet.autoOpenSecureChannel();
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    assertTrue(cmdSet.getKeyInitializationStatus());

    // Good case
    response = cmdSet.removeKey();
    assertEquals(0x9000, response.getSW());

    assertFalse(cmdSet.getKeyInitializationStatus());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
    data = response.getData();
    assertEquals(0, data[30 + data[21]]);
  }

  @Test
  @DisplayName("DERIVE KEY command")
  void deriveKeyTest() throws Exception {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00});
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();
    boolean autonomousDerivation = cmdSet.getPublicKeyDerivationSupport();

    // Security condition violation: PIN is not verified
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00});
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    // Condition violation: keyset is not extended
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00});
    assertEquals(0x6985, response.getSW());

    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSW());

    // Wrong P1/P2
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x6A86, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, false, true);
    assertEquals(0x6A86, response.getSW());

    // Wrong data format
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00});
    assertEquals(0x6A80, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00});
    assertEquals(0x6A80, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_MASTER,  true, false);
    assertEquals(0x6A80, response.getSW());


    if (autonomousDerivation) {
      // Correct
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01});
      assertEquals(0x9000, response.getSW());
      verifyKeyDerivation(keyPair, chainCode, new int[]{1});

      // 3 levels with hardened key
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01, (byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
      assertEquals(0x9000, response.getSW());
      verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 2});

      // From parent
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x03}, WalletApplet.DERIVE_P1_SOURCE_PARENT, false, false);
      assertEquals(0x9000, response.getSW());
      verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 3});

      // Reset master key
      response = cmdSet.deriveKey(new byte[0]);
      assertEquals(0x9000, response.getSW());
      verifyKeyDerivation(keyPair, chainCode, new int[0]);

      // Try parent when none available
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x03}, WalletApplet.DERIVE_P1_SOURCE_PARENT, false, false);
      assertEquals(0x6B00, response.getSW());

      // 3 levels with hardened key using separate commands
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER, false, false);
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(new byte[]{(byte) 0x80, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, false, false);
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, false, false);
      assertEquals(0x9000, response.getSW());
      verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 2});
    } else {
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01});
      assertEquals(0x6a81, response.getSW());
    }

    // Assisted derivation
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[] { 1 });

    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[] { 1, 2 });

    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x03}, WalletApplet.DERIVE_P1_SOURCE_PARENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[] { 1, 3 });

    // Try to derive two keys at once
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x6a86, response.getSW());

    // Reset master key
    response = cmdSet.deriveKey(new byte[0]);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[0]);

    // Try to sign and get key path before load public key, then resume loading public key
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    byte[] key = derivePublicKey(response.getData());
    response = cmdSet.sign(sha256("test".getBytes()), WalletApplet.SIGN_P1_PRECOMPUTED_HASH, true, true);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(key, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[] { 2 });

    // Reset master key
    response = cmdSet.deriveKey(new byte[0]);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[0]);
  }

  @Test
  @DisplayName("SIGN command")
  void signTest() throws Exception {
    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true,true);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    KeyPair keyPair = keypairGenerator().generateKeyPair();
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    signature.initVerify(keyPair.getPublic());

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());

    // Wrong P2: no active signing session but first block bit not set
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,false, false);
    assertEquals(0x6A86, response.getSW());

    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,false, true);
    assertEquals(0x6A86, response.getSW());

    // Correctly sign a precomputed hash
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x9000, response.getSW());
    byte[] sig = response.getData();
    byte[] keyData = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);
    assertEquals((SecureChannel.SC_KEY_LENGTH * 2 / 8) + 1, keyData.length);
    signature.update(data);
    assertTrue(signature.verify(sig));
    assertFalse(isMalleable(sig));
  }

  @Test
  @DisplayName("SET PINLESS PATH command")
  void setPinlessPathTest() throws Exception {
    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);

    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02});
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02});
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSW());

    // Wrong data
    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00});
    assertEquals(0x6a80, response.getSW());
    response = cmdSet.setPinlessPath(new byte[(WalletApplet.KEY_PATH_MAX_DEPTH + 1)* 4]);
    assertEquals(0x6a80, response.getSW());

    // Correct
    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02});
    assertEquals(0x9000, response.getSW());

    // Verify that only PINless path can be used without PIN
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x9000, response.getSW());

    // Verify changing path
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01});
    assertEquals(0x9000, response.getSW());
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x6985, response.getSW());
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x9000, response.getSW());

    // Reset
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.setPinlessPath(new byte[] {});
    assertEquals(0x9000, response.getSW());
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
    assertEquals(0x6985, response.getSW());
  }

  @Test
  @DisplayName("EXPORT KEY command")
  void exportKey() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSW());

    // Security condition violation: current key is not exportable
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.deriveKey(new byte[] { (byte) 0x80, 0x00, 0x00, 0x2c}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] { (byte) 0x80, 0x00, 0x00, 0x3c}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] { (byte) 0x80, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] { (byte) 0x00, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());


    // Export current public key (wrong P2)
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_ANY, false);
    assertEquals(0x6985, response.getSW());

    // Export current public key
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_ANY, true);
    assertEquals(0x9000, response.getSW());
    byte[] keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002c, 0x8000003c, 0x80000000, 0x00000000 }, true);

    response = cmdSet.deriveKey(new byte[] {(byte) 0xC0, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
    assertEquals(0x9000, response.getSW());

    // Wrong P1
    response = cmdSet.exportKey((byte) 3, false);
    assertEquals(0x6a86, response.getSW());

    // Correct
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x9000, response.getSW());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002c, 0x8000003c, 0x80000000, 0x00000000, 0xC0000001 }, false);

    // Correct public only
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, true);
    assertEquals(0x9000, response.getSW());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002c, 0x8000003c, 0x80000000, 0x00000000, 0xC0000001 }, true);

    // Reset
    response = cmdSet.deriveKey(new byte[] {}, WalletApplet.DERIVE_P1_SOURCE_MASTER, false, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportKey(WalletApplet.EXPORT_KEY_P1_HIGH, false);
    assertEquals(0x6985, response.getSW());
  }

  @Test
  @DisplayName("SIGN data (unused for the current scenario)")
  @Tag("manual")
  void signDataTest() throws Exception {
    Random r = new Random();
    byte[] data = new byte[SecureChannelSession.PAYLOAD_MAX_SIZE];
    byte[] smallData = Arrays.copyOf(data, 20);
    r.nextBytes(data);

    cmdSet.autoOpenSecureChannel();

    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    KeyPair keyPair = keypairGenerator().generateKeyPair();
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    signature.initVerify(keyPair.getPublic());

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());

    // Wrong P2: no active signing session but first block bit not set
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,false, false);
    assertEquals(0x6A86, response.getSW());

    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,false, true);
    assertEquals(0x6A86, response.getSW());

    // Correctly sign 1 block (P2: 0x81)
    response = cmdSet.sign(smallData, WalletApplet.SIGN_P1_DATA,true, true);
    assertEquals(0x9000, response.getSW());
    byte[] sig = extractSignature(response.getData());
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Correctly sign 2 blocks (P2: 0x01, 0x81)
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, WalletApplet.SIGN_P1_DATA,false, true);
    assertEquals(0x9000, response.getSW());
    sig = extractSignature(response.getData());
    signature.update(data);
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Correctly sign 3 blocks (P2: 0x01, 0x00, 0x80)
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,false, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, WalletApplet.SIGN_P1_DATA,false, true);
    assertEquals(0x9000, response.getSW());
    sig = extractSignature(response.getData());
    signature.update(data);
    signature.update(data);
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Re-start signing session by sending new first block
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, WalletApplet.SIGN_P1_DATA,true, true);
    assertEquals(0x9000, response.getSW());
    sig = extractSignature(response.getData());
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Abort signing session by loading new keys
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,true, false);
    assertEquals(0x9000, response.getSW());
    keyPair = keypairGenerator().generateKeyPair();
    signature.initVerify(keyPair.getPublic());
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, WalletApplet.SIGN_P1_DATA,false, true);
    assertEquals(0x6A86, response.getSW());

    // Signing session is aborted on reselection
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,true, false);
    assertEquals(0x9000, response.getSW());
    resetAndSelectAndOpenSC();
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, WalletApplet.SIGN_P1_DATA,false, true);
    assertEquals(0x6A86, response.getSW());

    // Signing session can be resumed if other commands are sent
    response = cmdSet.sign(data, WalletApplet.SIGN_P1_DATA,true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.changePIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, WalletApplet.SIGN_P1_DATA,false, true);
    assertEquals(0x9000, response.getSW());
    sig = extractSignature(response.getData());
    signature.update(data);
    signature.update(smallData);
    assertTrue(signature.verify(sig));
  }

  @Test
  @DisplayName("Sign actual Ethereum transaction")
  @Tag("manual")
  void signTransactionTest() throws Exception {
    // Initialize credentials
    Web3j web3j = Web3j.build(new HttpService());
    Credentials wallet1 = WalletUtils.loadCredentials("testwallet", "testwallets/wallet1.json");
    Credentials wallet2 = WalletUtils.loadCredentials("testwallet", "testwallets/wallet2.json");

    // Load keys on card
    cmdSet.autoOpenSecureChannel();
    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.loadKey(wallet1.getEcKeyPair());
    assertEquals(0x9000, response.getSW());

    // Verify balance
    System.out.println("Wallet 1 balance: " + web3j.ethGetBalance(wallet1.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance());
    System.out.println("Wallet 2 balance: " + web3j.ethGetBalance(wallet2.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance());

    // Create transaction
    BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
    BigInteger weiValue = Convert.toWei(BigDecimal.valueOf(1.0), Convert.Unit.FINNEY).toBigIntegerExact();
    BigInteger nonce = web3j.ethGetTransactionCount(wallet1.getAddress(), DefaultBlockParameterName.LATEST).send().getTransactionCount();

    RawTransaction rawTransaction = RawTransaction.createEtherTransaction(nonce, gasPrice, Transfer.GAS_LIMIT, wallet2.getAddress(), weiValue);

    // Sign transaction
    byte[] txBytes = TransactionEncoder.encode(rawTransaction);
    Sign.SignatureData signature = signMessage(txBytes);

    Method encode = TransactionEncoder.class.getDeclaredMethod("encode", RawTransaction.class, Sign.SignatureData.class);
    encode.setAccessible(true);

    // Send transaction
    byte[] signedMessage = (byte[]) encode.invoke(null, rawTransaction, signature);
    String hexValue = "0x" + Hex.toHexString(signedMessage);
    EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

    if (ethSendTransaction.hasError()) {
      System.out.println("Transaction Error: " + ethSendTransaction.getError().getMessage());
    }

    assertFalse(ethSendTransaction.hasError());
  }

  @Test
  @DisplayName("Performance Test with assisted key derivation")
  @Tag("manual")
  void performanceAssistedDerivationTest() throws Exception {
    long time, overhead = 0, deriveMaster = 0, deriveMasterHardened = 0, deriveCurrentHardened = 0, deriveCurrent = 0, deriveParent = 0, deriveParentHardened = 0, pubKey = 0;
    final long SAMPLE_COUNT = 10;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      ResponseAPDU response = apduChannel.transmit(new CommandAPDU(0x00, 0xAA, 0, 0, 0));
      overhead += System.currentTimeMillis() - time;
      assertEquals(0x6D00, response.getSW());
    }

    overhead /= SAMPLE_COUNT;

    System.out.println("Measuring key derivation performance. All times are expressed in milliseconds");
    System.out.println("***********************************************" );
    System.out.println("Java SmartCard I/O overhead: " + overhead);
    System.out.println("***********************************************" );

    // Prepare the card
    cmdSet.autoOpenSecureChannel();
    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSW());

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
      deriveMaster += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
      byte[] pub = derivePublicKey(response.getData());
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(pub, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      pubKey += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
    }

    deriveMaster /= SAMPLE_COUNT;
    pubKey /= SAMPLE_COUNT;

    System.out.println("Public key upload: " + pubKey + ". Without overhead: " + (pubKey - overhead));
    System.out.println("***********************************************" );
    System.out.println("Derivation time (1 level, non-hardened, from master): " + deriveMaster + ". Without overhead: " + (deriveMaster - overhead));
    System.out.println("Derivation + pubkey: " + (deriveMaster + pubKey) + ". Without overhead: " + (deriveMaster + pubKey - (overhead * 2)));
    System.out.println("***********************************************" );

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
      deriveMasterHardened += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      assertEquals(0x9000, response.getSW());
    }

    deriveMasterHardened /= SAMPLE_COUNT;

    System.out.println("Derivation time (1 level, hardened, from master): " + deriveMasterHardened + ". Without overhead: " + (deriveMasterHardened - overhead));
    System.out.println("Derivation + pubkey: " + (deriveMasterHardened + pubKey) + ". Without overhead: " + (deriveMasterHardened + pubKey - (overhead * 2)));
    System.out.println("***********************************************" );

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      assertEquals(0x9000, response.getSW());
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
      deriveCurrent += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      assertEquals(0x9000, response.getSW());
    }

    deriveCurrent /= SAMPLE_COUNT;

    System.out.println("Derivation time (1 level, non-hardened, from current): " + deriveCurrent + ". Without overhead: " + (deriveCurrent - overhead));
    System.out.println("Derivation + pubkey: " + (deriveCurrent + pubKey) + ". Without overhead: " + (deriveCurrent + pubKey - (overhead * 2)));
    System.out.println("***********************************************" );

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER, true, false);
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      assertEquals(0x9000, response.getSW());
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, false);
      deriveCurrentHardened += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      assertEquals(0x9000, response.getSW());
    }

    deriveCurrentHardened /= SAMPLE_COUNT;

    System.out.println("Derivation time (1 level, hardened, from current): " + deriveCurrentHardened + ". Without overhead: " + (deriveCurrentHardened - overhead));
    System.out.println("Derivation + pubkey: " + (deriveCurrentHardened + pubKey) + ". Without overhead: " + (deriveCurrentHardened + pubKey - (overhead * 2)));
    System.out.println("***********************************************" );

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, (byte) i}, WalletApplet.DERIVE_P1_SOURCE_PARENT, true, false);
      deriveParent += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      assertEquals(0x9000, response.getSW());
    }

    deriveParent /= SAMPLE_COUNT;

    System.out.println("Derivation time (1 level, non-hardened, from parent): " + deriveParent + ". Without overhead: " + (deriveParent - overhead));
    System.out.println("Derivation + pubkey: " + (deriveParent + pubKey) + ". Without overhead: " + (deriveParent + pubKey - (overhead * 2)));
    System.out.println("***********************************************" );

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, (byte) i}, WalletApplet.DERIVE_P1_SOURCE_PARENT, true, false);
      deriveParentHardened += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
      response = cmdSet.deriveKey(derivePublicKey(response.getData()), WalletApplet.DERIVE_P1_SOURCE_CURRENT, true, true);
      assertEquals(0x9000, response.getSW());
    }

    deriveParentHardened /= SAMPLE_COUNT;

    System.out.println("Derivation time (1 level, hardened, from parent): " + deriveParentHardened + ". Without overhead: " + (deriveParentHardened - overhead));
    System.out.println("Derivation + pubkey: " + (deriveParentHardened + pubKey) + ". Without overhead: " + (deriveParentHardened + pubKey - (overhead * 2)));
    System.out.println("***********************************************" );

    System.out.println("Estimated time to derive m/44'/60'/0'/0/0: " + (deriveMasterHardened + (deriveCurrentHardened * 2) + (deriveCurrent  * 2) + (pubKey * 5)));
    System.out.println("Estimated time to switch m/44'/60'/0'/0/0': " + (deriveParentHardened + pubKey));
    System.out.println("Estimated time to switch back to m/44'/60'/0'/0/0: " + (deriveParent + pubKey));
  }

  @Test
  @DisplayName("Performance Test with unassisted key derivation")
  @Tag("manual")
  void performanceUnassistedDerivationTest() throws Exception {
    long time, deriveAccount = 0, deriveParent = 0, deriveParentHardened = 0;
    final long SAMPLE_COUNT = 10;

    System.out.println("Measuring key derivation performance. All times are expressed in milliseconds");
    System.out.println("***********************************************" );

    // Prepare the card
    cmdSet.autoOpenSecureChannel();
    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSW());

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] { (byte) 0x80, 0x00, 0x00, 0x2C, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_MASTER, false, false);
      deriveAccount += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
    }

    deriveAccount /= SAMPLE_COUNT;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, (byte) i}, WalletApplet.DERIVE_P1_SOURCE_PARENT, false, false);
      deriveParent += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
    }

    deriveParent /= SAMPLE_COUNT;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, (byte) i}, WalletApplet.DERIVE_P1_SOURCE_PARENT, false, false);
      deriveParentHardened += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
    }

    deriveParentHardened /= SAMPLE_COUNT;

    System.out.println("Time to derive m/44'/60'/0'/0/0: " + deriveAccount);
    System.out.println("Time to switch m/44'/60'/0'/0/0': " + deriveParentHardened);
    System.out.println("Time to switch back to m/44'/60'/0'/0/0: " + deriveParent);
  }

  private KeyPairGenerator keypairGenerator() throws Exception {
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ecSpec);

    return g;
  }

  private byte[] extractSignature(byte[] sig) {
    int off = sig[4] + 5;
    return Arrays.copyOfRange(sig, off, off + sig[off + 1] + 2);
  }

  private byte[] extractPublicKeyFromSignature(byte[] sig) {
    assertEquals(WalletApplet.TLV_SIGNATURE_TEMPLATE, sig[0]);
    assertEquals((byte) 0x81, sig[1]);
    assertEquals(WalletApplet.TLV_PUB_KEY, sig[3]);

    return Arrays.copyOfRange(sig, 5, 5 + sig[4]);
  }

  private byte[] extractPublicKeyFromSelect(byte[] select) {
    assertEquals(WalletApplet.TLV_APPLICATION_INFO_TEMPLATE, select[0]);
    assertEquals(WalletApplet.TLV_UID, select[2]);
    assertEquals(WalletApplet.TLV_PUB_KEY, select[20]);

    return Arrays.copyOfRange(select, 22, 22 + select[21]);
  }

  private void reset() {
    if (USE_SIMULATOR) {
      simulator.reset();
    } else {
      apduChannel.getCard().getATR();
    }
  }

  private void resetAndSelectAndOpenSC() throws CardException {
    reset();
    cmdSet.select();
    cmdSet.autoOpenSecureChannel();
  }

  private void assertMnemonic(int expectedLength, byte[] data) {
    short[] shorts = new short[data.length / 2];
    assertEquals(expectedLength, shorts.length);
    ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).asShortBuffer().get(shorts);

    boolean[] bits = new boolean[11 * shorts.length];
    int i = 0;

    for (short mIdx : shorts) {
      assertTrue(mIdx >= 0 && mIdx < 2048);
      for (int j = 0; j < 11; ++j) {
        bits[i++] = (mIdx & (1 << (10 - j))) > 0;
      }
    }

    data = new byte[bits.length / 33 * 4];

    for (i = 0; i < bits.length / 33 * 32; ++i) {
      data[i / 8] |= (bits[i] ? 1 : 0) << (7 - (i % 8));
    }

    byte[] check = sha256(data);

    for (i = bits.length / 33 * 32; i < bits.length; ++i) {
      if ((check[(i - bits.length / 33 * 32) / 8] & (1 << (7 - (i % 8))) ^ (bits[i] ? 1 : 0) << (7 - (i % 8))) != 0) {
        fail("Checksum is invalid");
      }
    }
  }

  private void verifyKeyDerivation(KeyPair keyPair, byte[] chainCode, int[] path) throws Exception {
    DeterministicKey key = deriveKey(keyPair, chainCode, path);

    byte[] hash = Hash.sha3(new byte[8]);
    ResponseAPDU resp = cmdSet.sign(hash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH, true, true);
    assertEquals(0x9000, resp.getSW());
    byte[] sig = resp.getData();
    byte[] publicKey = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);

    assertTrue(key.verify(hash, sig));
    assertArrayEquals(key.getPubKeyPoint().getEncoded(false), publicKey);

    resp = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x9000, resp.getSW());
    byte[] rawPath = resp.getData();

    assertEquals(path.length * 4, rawPath.length);

    for (int i = 0; i < path.length; i++) {
      int k = path[i];
      int k1 = (rawPath[i * 4] << 24) | (rawPath[(i * 4) + 1] << 16) | (rawPath[(i * 4) + 2] << 8) | rawPath[(i * 4) + 3];
      assertEquals(k, k1);
    }
  }

  private void verifyExportedKey(byte[] keyTemplate, KeyPair keyPair, byte[] chainCode, int[] path, boolean publicOnly) {
    ECKey key = deriveKey(keyPair, chainCode, path).decompress();
    assertEquals(WalletApplet.TLV_KEY_TEMPLATE, keyTemplate[0]);
    assertEquals(WalletApplet.TLV_PUB_KEY, keyTemplate[2]);
    byte[] pubKey = Arrays.copyOfRange(keyTemplate, 4, 4 + keyTemplate[3]);
    assertArrayEquals(key.getPubKey(), pubKey);

    if (publicOnly) {
      assertEquals(pubKey.length + 2, keyTemplate[1]);
      assertEquals(pubKey.length + 4, keyTemplate.length);
    } else {
      assertEquals(WalletApplet.TLV_PRIV_KEY, keyTemplate[4 + pubKey.length]);
      byte[] privateKey = Arrays.copyOfRange(keyTemplate, 6 + pubKey.length, 6 + pubKey.length + keyTemplate[5 + pubKey.length]);

      byte[] tPrivKey = key.getPrivKey().toByteArray();

      if (tPrivKey[0] == 0x00) {
        tPrivKey = Arrays.copyOfRange(tPrivKey, 1, tPrivKey.length);
      }

      assertArrayEquals(tPrivKey, privateKey);
    }
  }

  private DeterministicKey deriveKey(KeyPair keyPair, byte[] chainCode, int[] path) {
    DeterministicKey key = HDKeyDerivation.createMasterPrivKeyFromBytes(((org.bouncycastle.jce.interfaces.ECPrivateKey) keyPair.getPrivate()).getD().toByteArray(), chainCode);

    for (int i : path) {
      key = HDKeyDerivation.deriveChildKey(key, new ChildNumber(i));
    }

    return key;
  }

  private boolean isMalleable(byte[] sig) {
    int rLen = sig[3];
    int sOff = 6 + rLen;
    int sLen = sig.length - rLen - 6;

    BigInteger s = new BigInteger(Arrays.copyOfRange(sig, sOff, sOff + sLen));
    BigInteger limit = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);

    return s.compareTo(limit) >= 1;
  }

  /**
   * This method takes the response from the first stage of an assisted key derivation command and derives the complete
   * public key from the received X and signature. Outside of test code, proper TLV parsing would be a better idea, here
   * we just assume that the data is where we expect it to be.
   *
   * The algorithm used to derive the public key is dead simple. We take the X and we preprend the 0x02 byte so it
   * becomes a compressed public key with even parity. We then try to verify the signature using this key. If it verifies
   * then we have found the key, otherwise we set the first byte to 0x03 to turn the key to odd parity. Again we try
   * to verify the signature using this key, it must work this time.
   *
   * We then uncompress the point we found and return it. This will be sent in the next DERIVE KEY command.
   *
   * @param data the unencrypted response from the card
   * @return the uncompressed public key
   */
  private byte[] derivePublicKey(byte[] data) {
    byte[] pubKey = Arrays.copyOfRange(data, 3, 4 + data[3]);
    byte[] signature = Arrays.copyOfRange(data, 4 + data[3], data.length);
    byte[] hash = sha256("STATUS KEY DERIVATION".getBytes());

    pubKey[0] = 0x02;
    ECKey candidate = ECKey.fromPublicOnly(pubKey);
    if (!candidate.verify(hash, signature)) {
      pubKey[0] = 0x03;
      candidate = ECKey.fromPublicOnly(pubKey);
      assertTrue(candidate.verify(hash, signature));
    }

    return candidate.decompress().getPubKey();
  }

  /**
   * Signs a signature using the card. Returns a SignatureData object which contains v, r and s. The algorithm to do
   * this is as follow:
   *
   * 1) The Keccak-256 hash of transaction is generated off-card
   * 2) A SIGN command is sent to the card to sign the precomputed hash
   * 3) The returned data is the public key and the signature
   * 4) The signature and public key can be used to generate the v value. The v value allows to recover the public key
   *    from the signature. Here we use the web3j implementation through reflection
   * 5) v, r and s are the final signature to append to the transaction
   *
   * @param message the raw transaction
   * @return the signature data
   */
  private Sign.SignatureData signMessage(byte[] message) throws Exception {
    byte[] messageHash = Hash.sha3(message);

    ResponseAPDU response = cmdSet.sign(messageHash, WalletApplet.SIGN_P1_PRECOMPUTED_HASH,true, true);
    assertEquals(0x9000, response.getSW());
    byte[] respData = response.getData();
    byte[] rawSig = extractSignature(respData);

    int rLen = rawSig[3];
    int sOff = 6 + rLen;
    int sLen = rawSig.length - rLen - 6;

    BigInteger r = new BigInteger(Arrays.copyOfRange(rawSig, 4, 4 + rLen));
    BigInteger s = new BigInteger(Arrays.copyOfRange(rawSig, sOff, sOff + sLen));

    Class<?> ecdsaSignature = Class.forName("org.web3j.crypto.Sign$ECDSASignature");
    Constructor ecdsaSignatureConstructor = ecdsaSignature.getDeclaredConstructor(BigInteger.class, BigInteger.class);
    ecdsaSignatureConstructor.setAccessible(true);
    Object sig = ecdsaSignatureConstructor.newInstance(r, s);
    Method m = ecdsaSignature.getMethod("toCanonicalised");
    m.setAccessible(true);
    sig = m.invoke(sig);

    Method recoverFromSignature = Sign.class.getDeclaredMethod("recoverFromSignature", int.class, ecdsaSignature, byte[].class);
    recoverFromSignature.setAccessible(true);

    byte[] pubData = extractPublicKeyFromSignature(respData);
    BigInteger publicKey = new BigInteger(Arrays.copyOfRange(pubData, 1, pubData.length));

    int recId = -1;
    for (int i = 0; i < 4; i++) {
      BigInteger k = (BigInteger) recoverFromSignature.invoke(null, i, sig, messageHash);
      if (k != null && k.equals(publicKey)) {
        recId = i;
        break;
      }
    }
    if (recId == -1) {
      throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
    }

    int headerByte = recId + 27;

    Field rF = ecdsaSignature.getDeclaredField("r");
    rF.setAccessible(true);
    Field sF = ecdsaSignature.getDeclaredField("s");
    sF.setAccessible(true);
    r = (BigInteger) rF.get(sig);
    s = (BigInteger) sF.get(sig);

    // 1 header + 32 bytes for R + 32 bytes for S
    byte v = (byte) headerByte;
    byte[] rB = Numeric.toBytesPadded(r, 32);
    byte[] sB = Numeric.toBytesPadded(s, 32);

    return new Sign.SignatureData(v, rB, sB);
  }

  private void verifyKeyUID(byte[] keyUID, ECPublicKey pubKey) {
    verifyKeyUID(keyUID, pubKey.getQ().getEncoded(false));
  }

  private void verifyKeyUID(byte[] keyUID, byte[] pubKey) {
    assertArrayEquals(sha256(pubKey), keyUID);
  }
}

package im.status.wallet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.hardwallet.lite.WalletAppletCommandSet;
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

  private TestSecureChannelSession secureChannel;
  private TestWalletAppletCommandSet cmdSet;

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
      simulator.installApplet(appletAID, WalletApplet.class);
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

    initIfNeeded();
  }

  private static void initIfNeeded() throws CardException {
    WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(apduChannel);
    byte[] data = cmdSet.select().getData();
    if (data[0] == WalletApplet.TLV_APPLICATION_INFO_TEMPLATE) return;
    assertEquals(0x9000, cmdSet.init("000000", "123456789012", SHARED_SECRET).getSW());
  }

  @BeforeEach
  void init() throws CardException {
    reset();
    cmdSet = new TestWalletAppletCommandSet(apduChannel);
    secureChannel = new TestSecureChannelSession();
    cmdSet.setSecureChannel(secureChannel);
    WalletAppletCommandSet.checkOK(cmdSet.select());
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

    // Verify that the keys are changed correctly. Since we do not know the internal counter we just iterate until that
    // happens for a maximum of SC_COUNTER_MAX times
    byte[] initialKey = extractPublicKeyFromSelect(cmdSet.select().getData());

    for (int i = 0; i < SecureChannel.SC_COUNTER_MAX; i++) {
      byte[] otherKey = extractPublicKeyFromSelect(cmdSet.select().getData());

      if (!Arrays.equals(initialKey, otherKey)) {
        secureChannel.generateSecret(otherKey);
        cmdSet.autoOpenSecureChannel();
        break;
      }
    }
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
    assertTrue(Hex.toHexString(data).matches("a30c0201030201050101[0f][0f]"));

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());
    data = response.getData();
    assertTrue(Hex.toHexString(data).matches("a30c0201020201050101[0f][0f]"));

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSW());
    data = response.getData();
    assertTrue(Hex.toHexString(data).matches("a30c0201030201050101[0f][0f]"));

    // Check that key path is empty
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x9000, response.getSW());
    data = response.getData();
    assertEquals(0, data.length);
  }

  @Test
  @DisplayName("SET NDEF command")
  void setNDEFTest() throws CardException {
    byte[] ndefData = {
        (byte) 0x00, (byte) 0x24, (byte) 0xd4, (byte) 0x0f, (byte) 0x12, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
        (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d,
        (byte) 0x3a, (byte) 0x70, (byte) 0x6b, (byte) 0x67, (byte) 0x69, (byte) 0x6d, (byte) 0x2e, (byte) 0x73,
        (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x75, (byte) 0x73, (byte) 0x2e, (byte) 0x65, (byte) 0x74,
        (byte) 0x68, (byte) 0x65, (byte) 0x72, (byte) 0x65, (byte) 0x75, (byte) 0x6d
    };

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.setNDEF(ndefData);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.setNDEF(ndefData);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Good case.
    response = cmdSet.setNDEF(ndefData);
    assertEquals(0x9000, response.getSW());

    // Wrong length
    ndefData[1]++;
    response = cmdSet.setNDEF(ndefData);
    assertEquals(0x6A80, response.getSW());
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
    ResponseAPDU response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN n ot verified
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Wrong P1
    response = cmdSet.changePIN(0x03, "123456");
    assertEquals(0x6a86, response.getSW());

    // Test wrong PIN formats (non-digits, too short, too long)
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "654a21");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "54321");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "7654321");
    assertEquals(0x6A80, response.getSW());

    // Test wrong PUK formats
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PUK, "210987654a21");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PUK, "10987654321");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PUK, "3210987654321");
    assertEquals(0x6A80, response.getSW());

    // Test wrong pairing secret format (too long, too short)
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PAIRING_SECRET, "abcdefghilmnopqrstuvz123456789012");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PAIRING_SECRET, "abcdefghilmnopqrstuvz1234567890");
    assertEquals(0x6A80, response.getSW());

    // Change PIN correctly, check that after PIN change the PIN remains validated
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "654321");
    assertEquals(0x9000, response.getSW());

    // Reset card and verify that the new PIN has really been set
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSW());

    // Change PUK
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PUK, "210987654321");
    assertEquals(0x9000, response.getSW());

    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C2, response.getSW());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C1, response.getSW());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSW());

    // Reset the PIN with the new PUK
    response = cmdSet.unblockPIN("210987654321", "000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Reset PUK
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PUK, "123456789012");
    assertEquals(0x9000, response.getSW());

    // Change the pairing secret
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PAIRING_SECRET, "abcdefghilmnopqrstuvz12345678901");
    assertEquals(0x9000, response.getSW());
    cmdSet.autoUnpair();
    reset();
    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
    cmdSet.autoPair("abcdefghilmnopqrstuvz12345678901".getBytes());

    // Reset pairing secret
    cmdSet.autoOpenSecureChannel();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_PAIRING_SECRET, SHARED_SECRET);
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
    response = cmdSet.changePIN(WalletApplet.CHANGE_PIN_P1_USER_PIN, "000000");
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
    assertEquals(0x9000, response.getSW());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));
    response = cmdSet.loadKey(keyPair, true, chainCode);
    assertEquals(0x9000, response.getSW());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    // Check seed load
    response = cmdSet.loadKey(keyPair.getPrivate(), chainCode);
    assertEquals(0x9000, response.getSW());
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
  @DisplayName("GENERATE KEY command")
  void generateKeyTest() throws Exception {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.generateKey();
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.generateKey();
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Good case
    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSW());
    byte[] keyUID = response.getData();

    response = cmdSet.exportCurrentKey(true);
    assertEquals(0x9000, response.getSW());
    byte[] pubKey = response.getData();

    verifyKeyUID(keyUID, Arrays.copyOfRange(pubKey, 4, pubKey.length));
  }

  @Test
  @DisplayName("DERIVE KEY command")
  void deriveKeyTest() throws Exception {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00});
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

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

    // Wrong data format
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00});
    assertEquals(0x6A80, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00});
    assertEquals(0x6A80, response.getSW());

    // Correct
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01});
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1});

    // 3 levels with hardened key
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01, (byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 2});

    // From parent
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x03}, WalletApplet.DERIVE_P1_SOURCE_PARENT);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 3});

    // Reset master key
    response = cmdSet.deriveKey(new byte[0]);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[0]);

    // Try parent when none available
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x03}, WalletApplet.DERIVE_P1_SOURCE_PARENT);
    assertEquals(0x6B00, response.getSW());

    // 3 levels with hardened key using separate commands
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(new byte[]{(byte) 0x80, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_CURRENT);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT);
    assertEquals(0x9000, response.getSW());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 2});

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
    ResponseAPDU response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    KeyPair keyPair = keypairGenerator().generateKeyPair();
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    signature.initVerify(keyPair.getPublic());

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());

    // Wrong Data length
    response = cmdSet.sign(data);
    assertEquals(0x6A80, response.getSW());

    // Correctly sign a precomputed hash
    response = cmdSet.sign(hash);
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
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_CURRENT);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(hash);
    assertEquals(0x9000, response.getSW());

    // Verify changing path
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01});
    assertEquals(0x9000, response.getSW());
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSW());
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(hash);
    assertEquals(0x9000, response.getSW());

    // Reset
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.setPinlessPath(new byte[] {});
    assertEquals(0x9000, response.getSW());
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSW());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, WalletApplet.DERIVE_P1_SOURCE_MASTER);
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
    ResponseAPDU response = cmdSet.exportCurrentKey(true);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.exportCurrentKey(true);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSW());

    // Security condition violation: current key is not exportable
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2c, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x6985, response.getSW());


    // Export current public key
    response = cmdSet.exportCurrentKey(true);
    assertEquals(0x9000, response.getSW());
    byte[] keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000 }, true, false);

    // Derive & Make current
    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_MASTER,true,false);
    assertEquals(0x9000, response.getSW());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000, 0x00000000 }, false, false);

    // Derive without making current
    response = cmdSet.exportKey(new byte[] {(byte) 0x00, 0x00, 0x00, 0x01}, WalletApplet.DERIVE_P1_SOURCE_PARENT, false,false);
    assertEquals(0x9000, response.getSW());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000, 0x00000001 }, false, true);
    response = cmdSet.getStatus(WalletApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x9000, response.getSW());
    assertArrayEquals(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, response.getData());

    // Export current
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x9000, response.getSW());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000, 0x00000000 }, false, false);

    // Reset
    response = cmdSet.deriveKey(new byte[0], WalletApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("DUPLICATE KEY command")
  void duplicateTest() throws Exception {
    int secretCount = 5;
    Random random = new Random();
    byte[][] secrets = new byte[secretCount][32];
    for (int i = 0; i < secretCount; i++) {
      random.nextBytes(secrets[i]);
    }

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.duplicateKeyStart(secretCount, secrets[0]);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.duplicateKeyStart(secretCount, secrets[0]);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSW());
    byte[] keyUID = response.getData();

    // Init duplication
    response = cmdSet.duplicateKeyStart(secretCount, secrets[0]);
    assertEquals(0x9000, response.getSW());

    // Adding key entropy must work without secure channel and PIN authentication
    reset();
    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());

    // Put all except the last piece of entropy
    for (int i = 1; i < (secretCount - 1); i++) {
      response = cmdSet.duplicateKeyAddEntropy(secrets[i]);
      assertEquals(0x9000, response.getSW());
    }

    cmdSet.autoOpenSecureChannel();
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Try to backup before enough entropy has been set
    response = cmdSet.duplicateKeyExport();
    assertEquals(0x6985, response.getSW());

    reset();
    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());

    // Put last piece of entropy
    response = cmdSet.duplicateKeyAddEntropy(secrets[(secretCount - 1)]);
    assertEquals(0x9000, response.getSW());

    // Try putting more entropy (failure expected)
    response = cmdSet.duplicateKeyAddEntropy(secrets[(secretCount - 1)]);
    assertEquals(0x6985, response.getSW());

    cmdSet.autoOpenSecureChannel();
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Backup
    response = cmdSet.duplicateKeyExport();
    assertEquals(0x9000, response.getSW());
    byte[] backup = response.getData();

    // Try to restore the backup (failure expected, session is over)
    response = cmdSet.duplicateKeyImport(backup);
    assertEquals(0x6985, response.getSW());

    // Now try to restore the backup and check that the key UID matches, but first change the keys to random ones
    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSW());

    response = cmdSet.duplicateKeyStart(secretCount, secrets[0]);
    assertEquals(0x9000, response.getSW());

    reset();
    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());

    for (int i = 1; i < secretCount; i++) {
      response = cmdSet.duplicateKeyAddEntropy(secrets[i]);
      assertEquals(0x9000, response.getSW());
    }

    cmdSet.autoOpenSecureChannel();
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.duplicateKeyImport(backup);
    assertEquals(0x9000, response.getSW());
    assertArrayEquals(keyUID, response.getData());
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
  @DisplayName("Performance Test")
  @Tag("manual")
  void performanceTest() throws Exception {
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
      response = cmdSet.deriveKey(new byte[] { (byte) 0x80, 0x00, 0x00, 0x2C, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, WalletApplet.DERIVE_P1_SOURCE_MASTER);
      deriveAccount += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
    }

    deriveAccount /= SAMPLE_COUNT;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, (byte) i}, WalletApplet.DERIVE_P1_SOURCE_PARENT);
      deriveParent += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSW());
    }

    deriveParent /= SAMPLE_COUNT;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, (byte) i}, WalletApplet.DERIVE_P1_SOURCE_PARENT);
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
    ResponseAPDU resp = cmdSet.sign(hash);
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

  private void verifyExportedKey(byte[] keyTemplate, KeyPair keyPair, byte[] chainCode, int[] path, boolean publicOnly, boolean noPubKey) {
    ECKey key = deriveKey(keyPair, chainCode, path).decompress();
    assertEquals(WalletApplet.TLV_KEY_TEMPLATE, keyTemplate[0]);
    int pubKeyLen = 0;

    if (!noPubKey) {
      assertEquals(WalletApplet.TLV_PUB_KEY, keyTemplate[2]);
      byte[] pubKey = Arrays.copyOfRange(keyTemplate, 4, 4 + keyTemplate[3]);
      assertArrayEquals(key.getPubKey(), pubKey);
      pubKeyLen = 2 + pubKey.length;
    }

    if (publicOnly) {
      assertEquals(pubKeyLen, keyTemplate[1]);
      assertEquals(pubKeyLen + 2, keyTemplate.length);
    } else {
      assertEquals(WalletApplet.TLV_PRIV_KEY, keyTemplate[2 + pubKeyLen]);
      byte[] privateKey = Arrays.copyOfRange(keyTemplate, 4 + pubKeyLen, 4 + pubKeyLen + keyTemplate[3 + pubKeyLen]);

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

    ResponseAPDU response = cmdSet.sign(messageHash);
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

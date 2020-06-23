package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.applet.*;
import im.status.keycard.desktop.LedgerUSBManager;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardListener;
import javacard.framework.AID;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
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
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import static org.apache.commons.codec.digest.DigestUtils.sha256;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Test the Keycard Applet")
public class KeycardTest {
  // Pairing key is KeycardTest
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;
  private static im.status.keycard.io.CardChannel sdkChannel;
  private static CardSimulator simulator;

  private static LedgerUSBManager usbManager;

  private static byte[] sharedSecret;

  private TestSecureChannelSession secureChannel;
  private TestKeycardCommandSet cmdSet;

  private static final int TARGET_SIMULATOR = 0;
  private static final int TARGET_CARD = 1;
  private static final int TARGET_LEDGERUSB = 2;

  private static final int TARGET;

  static {
    switch(System.getProperty("im.status.keycard.test.target", "card")) {
      case "simulator":
        TARGET = TARGET_SIMULATOR;
        break;
      case "card":
        TARGET = TARGET_CARD;
        break;
      case "ledgerusb":
        TARGET = TARGET_LEDGERUSB;
        break;
      default:
        throw new RuntimeException("Unknown target");
    }
  }

  @BeforeAll
  static void initAll() throws Exception {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        openSimulatorChannel();
        break;
      case TARGET_CARD:
        openCardChannel();
        break;
      case TARGET_LEDGERUSB:
        openLedgerUSBChannel();
        break;
      default:
        throw new IllegalStateException("Unknown target");
    }

    initIfNeeded();
  }

  private static void initCapabilities(ApplicationInfo info) {
    HashSet<String> capabilities = new HashSet<>();

    if (info.hasSecureChannelCapability()) {
      capabilities.add("secureChannel");
    }

    if (info.hasCredentialsManagementCapability()) {
      capabilities.add("credentialsManagement");
    }

    if (info.hasKeyManagementCapability()) {
      capabilities.add("keyManagement");
    }

    if (info.hasNDEFCapability()) {
      capabilities.add("ndef");
    }

    CapabilityCondition.availableCapabilities = capabilities;
  }

  private static void openSimulatorChannel() throws Exception {
    simulator = new CardSimulator();

    // Install KeycardApplet
    AID aid = AIDUtil.create(Identifiers.KEYCARD_AID);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(Identifiers.getKeycardInstanceAID().length);
    bos.write(Identifiers.getKeycardInstanceAID());

    simulator.installApplet(aid, KeycardApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install NDEFApplet
    aid = AIDUtil.create(Identifiers.NDEF_AID);
    bos.write(Identifiers.NDEF_INSTANCE_AID.length);
    bos.write(Identifiers.NDEF_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, NDEFApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install CashApplet
    aid = AIDUtil.create(Identifiers.CASH_AID);
    bos.write(Identifiers.CASH_INSTANCE_AID.length);
    bos.write(Identifiers.CASH_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, CashApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    cardTerminal = CardTerminalSimulator.terminal(simulator);

    openPCSCChannel();
  }

  private static void openCardChannel() throws Exception {
    TerminalFactory tf = TerminalFactory.getDefault();

    for (CardTerminal t : tf.terminals().list()) {
      if (t.isCardPresent()) {
        cardTerminal = t;
        break;
      }
    }

    openPCSCChannel();
  }

  private static void openPCSCChannel() throws Exception {
    Card apduCard = cardTerminal.connect("*");
    apduChannel = apduCard.getBasicChannel();
    sdkChannel = new PCSCCardChannel(apduChannel);
  }

  private static void openLedgerUSBChannel() {
    usbManager = new LedgerUSBManager(new CardListener() {
      @Override
      public void onConnected(im.status.keycard.io.CardChannel channel) {
        sdkChannel = channel;
      }

      @Override
      public void onDisconnected() {
        throw new RuntimeException("Ledger was disconnected during test run!");
      }
    });

    usbManager.start();
  }

  private static void initIfNeeded() throws Exception {
    KeycardCommandSet cmdSet = new KeycardCommandSet(sdkChannel);
    cmdSet.select().checkOK();

    initCapabilities(cmdSet.getApplicationInfo());

    sharedSecret = cmdSet.pairingPasswordToSecret(System.getProperty("im.status.keycard.test.pairing", "KeycardTest"));

    if (!cmdSet.getApplicationInfo().isInitializedCard()) {
      assertEquals(0x9000, cmdSet.init("000000", "123456789012", sharedSecret).getSw());
      cmdSet.select().checkOK();
      initCapabilities(cmdSet.getApplicationInfo());
    }
  }

  @BeforeEach
  void init() throws Exception {
    reset();
    cmdSet = new TestKeycardCommandSet(sdkChannel);
    secureChannel = new TestSecureChannelSession();
    cmdSet.setSecureChannel(secureChannel);
    cmdSet.select().checkOK();

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoPair(sharedSecret);
    }
  }

  @AfterEach
  void tearDown() throws Exception {
    resetAndSelectAndOpenSC();

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      APDUResponse response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoUnpair();
    }
  }

  @AfterAll
  static void tearDownAll() {
    if (usbManager != null) {
      usbManager.stop();
    }
  }

  @Test
  @DisplayName("SELECT command")
  void selectTest() throws Exception {
    APDUResponse response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    byte[] data = response.getData();
    assertTrue(new ApplicationInfo(data).isInitializedCard());
  }

  @Test
  @DisplayName("OPEN SECURE CHANNEL command")
  @Capabilities("secureChannel")
  void openSecureChannelTest() throws Exception {
    // Wrong P1
    APDUResponse response = cmdSet.openSecureChannel((byte)(secureChannel.getPairingIndex() + 1), new byte[65]);
    assertEquals(0x6A86, response.getSw());

    // Wrong data
    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), new byte[66]);
    assertEquals(0x6A80, response.getSw());

    // Good case
    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSw());
    assertEquals(SecureChannel.SC_SECRET_LENGTH + SecureChannel.SC_BLOCK_SIZE, response.getData().length);
    secureChannel.processOpenSecureChannelResponse(response);

    // Send command before MUTUALLY AUTHENTICATE
    secureChannel.reset();
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x6985, response.getSw());

    // Perform mutual authentication
    secureChannel.setOpen();
    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x9000, response.getSw());

    try {
      secureChannel.verifyMutuallyAuthenticateResponse(response);
    } catch (Exception e) {
      fail("invalid mutually authenticate response");
    }

    // Verify that the channel is open
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("MUTUALLY AUTHENTICATE command")
  @Capabilities("secureChannel")
  void mutuallyAuthenticateTest() throws Exception {
    // Mutual authentication before opening a Secure Channel
    APDUResponse response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSw());

    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSw());
    secureChannel.processOpenSecureChannelResponse(response);

    // Wrong data format
    response = cmdSet.mutuallyAuthenticate(new byte[31]);
    assertEquals(0x6982, response.getSw());

    // Verify that after wrong authentication, the command does not work
    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSw());

    // Wrong authentication data
    response = cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSw());
    secureChannel.processOpenSecureChannelResponse(response);
    APDUResponse resp2 = sdkChannel.send(new APDUCommand(0x80, SecureChannel.INS_MUTUALLY_AUTHENTICATE, 0, 0, new byte[48]));
    assertEquals(0x6982, resp2.getSw());
    secureChannel.reset();
    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSw());

    // Good case
    cmdSet.autoOpenSecureChannel();

    // MUTUALLY AUTHENTICATE has no effect on an already open secure channel
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.mutuallyAuthenticate();
    assertEquals(0x6985, response.getSw());

    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("PAIR command")
  @Capabilities("secureChannel")
  void pairTest() throws Exception {
    // Wrong data length
    APDUResponse response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, new byte[31]);
    assertEquals(0x6A80, response.getSw());

    // Wrong P1
    response = cmdSet.pair(SecureChannel.PAIR_P1_LAST_STEP, new byte[32]);
    assertEquals(0x6A86, response.getSw());

    // Wrong client cryptogram
    byte[] challenge = new byte[32];
    Random random = new Random();
    random.nextBytes(challenge);
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertEquals(0x9000, response.getSw());
    response = cmdSet.pair(SecureChannel.PAIR_P1_LAST_STEP, challenge);
    assertEquals(0x6982, response.getSw());

    // Interrupt session
    random.nextBytes(challenge);
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertEquals(0x9000, response.getSw());
    cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    response = cmdSet.pair(SecureChannel.PAIR_P1_LAST_STEP, challenge);
    assertEquals(0x6A86, response.getSw());

    // Open secure channel
    cmdSet.autoOpenSecureChannel();
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertTrue((0x6985 == response.getSw()) || (0x6982 == response.getSw()));
    cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());

    // Pair multiple indexes
    for (int i = 1; i < KeycardApplet.PAIRING_MAX_CLIENT_COUNT; i++) {
      cmdSet.autoPair(sharedSecret);
      assertEquals(i, secureChannel.getPairingIndex());
      cmdSet.autoOpenSecureChannel();
      cmdSet.openSecureChannel(secureChannel.getPairingIndex(), secureChannel.getPublicKey());
    }

    // Too many paired indexes
    response = cmdSet.pair(SecureChannel.PAIR_P1_FIRST_STEP, challenge);
    assertEquals(0x6A84, response.getSw());

    // Unpair all (except the last, which will be unpaired in the tearDown phase)
    cmdSet.autoOpenSecureChannel();

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    for (byte i = 0; i < (KeycardApplet.PAIRING_MAX_CLIENT_COUNT - 1); i++) {
      response = cmdSet.unpair(i);
      assertEquals(0x9000, response.getSw());
    }
  }

  @Test
  @DisplayName("UNPAIR command")
  @Capabilities("secureChannel")
  void unpairTest() throws Exception {
    // Add a spare keyset
    byte sparePairingIndex = secureChannel.getPairingIndex();
    cmdSet.autoPair(sharedSecret);

    // Proof that the old keyset is still usable
    APDUResponse response = cmdSet.openSecureChannel(sparePairingIndex, secureChannel.getPublicKey());
    assertEquals(0x9000, response.getSw());

    // Security condition violation: SecureChannel not open
    response = cmdSet.unpair(sparePairingIndex);
    assertEquals(0x6985, response.getSw());

    // Not authenticated
    cmdSet.autoOpenSecureChannel();

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.unpair(sparePairingIndex);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Wrong P1
    response = cmdSet.unpair((byte) 5);
    assertEquals(0x6A86, response.getSw());

    // Unpair spare keyset
    response = cmdSet.unpair(sparePairingIndex);
    assertEquals(0x9000, response.getSw());

    // Proof that unpaired is not usable
    response = cmdSet.openSecureChannel(sparePairingIndex, secureChannel.getPublicKey());
    assertEquals(0x6A86, response.getSw());
  }

  @Test
  @DisplayName("GET STATUS command")
  void getStatusTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    // Good case. Since the order of test execution is undefined, the test cannot know if the keys are initialized or not.
    // Additionally, support for public key derivation is hw dependent.
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSw());
    ApplicationStatus status = new ApplicationStatus(response.getData());

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      assertEquals(3, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());

      response = cmdSet.verifyPIN("123456");
      assertEquals(0x63C2, response.getSw());
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x9000, response.getSw());
      status = new ApplicationStatus(response.getData());
      assertEquals(2, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x9000, response.getSw());
      status = new ApplicationStatus(response.getData());
      assertEquals(3, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());
    } else {
      assertEquals((byte) 0xff, status.getPINRetryCount());
      assertEquals((byte) 0xff, status.getPUKRetryCount());
    }

    // Check that key path is valid
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x9000, response.getSw());
    KeyPath path = new KeyPath(response.getData());
    assertNotEquals(null, path);
  }

  @Test
  @DisplayName("VERIFY PIN command")
  @Capabilities("credentialsManagement")
  void verifyPinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Wrong format
    response = cmdSet.verifyPIN("12345");
    assertEquals(0x6a80, response.getSw());

    response = cmdSet.verifyPIN("12345a");
    assertEquals(0x6a80, response.getSw());

    // Wrong PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    // Correct PIN
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Check max retry counter
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSw());

    // Unblock PIN to make further tests possible
    response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("CHANGE PIN command")
  @Capabilities("credentialsManagement")
  void changePinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN n ot verified
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Wrong P1
    response = cmdSet.changePIN(0x03, "123456");
    assertEquals(0x6a86, response.getSw());

    // Test wrong PIN formats (non-digits, too short, too long)
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "654a21");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "54321");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "7654321");
    assertEquals(0x6A80, response.getSw());

    // Test wrong PUK formats
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "210987654a21");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "10987654321");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "3210987654321");
    assertEquals(0x6A80, response.getSw());

    // Test wrong pairing secret format (too long, too short)
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PAIRING_SECRET, "abcdefghilmnopqrstuvz123456789012");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PAIRING_SECRET, "abcdefghilmnopqrstuvz1234567890");
    assertEquals(0x6A80, response.getSw());

    // Change PIN correctly, check that after PIN change the PIN remains validated
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "654321");
    assertEquals(0x9000, response.getSw());

    // Reset card and verify that the new PIN has really been set
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSw());

    // Change PUK
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "210987654321");
    assertEquals(0x9000, response.getSw());

    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C2, response.getSw());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C1, response.getSw());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSw());

    // Reset the PIN with the new PUK
    response = cmdSet.unblockPIN("210987654321", "000000");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Reset PUK
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "123456789012");
    assertEquals(0x9000, response.getSw());

    // Change the pairing secret
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PAIRING_SECRET, "abcdefghilmnopqrstuvz12345678901");
    assertEquals(0x9000, response.getSw());
    cmdSet.autoUnpair();
    reset();
    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    cmdSet.autoPair("abcdefghilmnopqrstuvz12345678901".getBytes());

    // Reset pairing secret
    cmdSet.autoOpenSecureChannel();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PAIRING_SECRET, sharedSecret);
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("UNBLOCK PIN command")
  @Capabilities("credentialsManagement")
  void unblockPinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Condition violation: PIN is not blocked
    response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x6985, response.getSw());

    // Block the PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSw());

    // Wrong PUK formats (too short, too long)
    response = cmdSet.unblockPIN("12345678901", "000000");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.unblockPIN("1234567890123", "000000");
    assertEquals(0x6A80, response.getSw());

    // Wrong PUK
    response = cmdSet.unblockPIN("123456789010", "000000");
    assertEquals(0x63C4, response.getSw());

    // Correct PUK
    response = cmdSet.unblockPIN("123456789012", "654321");
    assertEquals(0x9000, response.getSw());

    // Check that PIN has been changed and unblocked
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSw());

    // Reset the PIN to make further tests possible
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "000000");
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("LOAD KEY command")
  @Capabilities("keyManagement")
  void loadKeyTest() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.loadKey(keyPair);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.loadKey(keyPair);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Wrong key type
    response = cmdSet.loadKey(new byte[] { (byte) 0xAA, 0x02, (byte) 0x80, 0x00}, (byte) 0x00);
    assertEquals(0x6A86, response.getSw());

    // Wrong data (wrong template, missing private key, invalid keys)
    response = cmdSet.loadKey(new byte[]{(byte) 0xAA, 0x02, (byte) 0x80, 0x00}, KeycardApplet.LOAD_KEY_P1_EC);
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.loadKey(new byte[]{(byte) 0xA1, 0x02, (byte) 0x80, 0x00}, KeycardApplet.LOAD_KEY_P1_EC);
    assertEquals(0x6A80, response.getSw());

    if (TARGET != TARGET_SIMULATOR) { // the simulator does not check the key format
      response = cmdSet.loadKey(new byte[]{(byte) 0xA1, 0x06, (byte) 0x80, 0x01, 0x01, (byte) 0x81, 0x01, 0x02}, KeycardApplet.LOAD_KEY_P1_EC);
      assertEquals(0x6A80, response.getSw());
    }

    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    // Correct LOAD KEY
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    keyPair = g.generateKeyPair();

    // Check extended key
    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    // Check omitted public key
    response = cmdSet.loadKey(keyPair, true, null);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));
    response = cmdSet.loadKey(keyPair, true, chainCode);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    // Check seed load
    response = cmdSet.loadKey(keyPair.getPrivate(), chainCode);
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("GENERATE MNEMONIC command")
  @Capabilities("keyManagement")
  void generateMnemonicTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      response = cmdSet.generateMnemonic(4);
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    // Wrong P1 (too short, too long)
    response = cmdSet.generateMnemonic(3);
    assertEquals(0x6A86, response.getSw());

    response = cmdSet.generateMnemonic(9);
    assertEquals(0x6A86, response.getSw());

    // Good cases
    response = cmdSet.generateMnemonic(4);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(12, response.getData());

    response = cmdSet.generateMnemonic(5);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(15, response.getData());

    response = cmdSet.generateMnemonic(6);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(18, response.getData());

    response = cmdSet.generateMnemonic(7);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(21, response.getData());

    response = cmdSet.generateMnemonic(8);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(24, response.getData());
  }

  @Test
  @DisplayName("REMOVE KEY command")
  @Capabilities("keyManagement")
  void removeKeyTest() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.removeKey();
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.removeKey();
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    ApplicationInfo info = new ApplicationInfo(response.getData());
    verifyKeyUID(info.getKeyUID(), (ECPublicKey) keyPair.getPublic());

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    assertTrue(cmdSet.getKeyInitializationStatus());

    // Good case
    response = cmdSet.removeKey();
    assertEquals(0x9000, response.getSw());

    assertFalse(cmdSet.getKeyInitializationStatus());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    info = new ApplicationInfo(response.getData());
    assertEquals(0, info.getKeyUID().length);
  }

  @Test
  @DisplayName("GENERATE KEY command")
  @Capabilities("keyManagement")
  void generateKeyTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.generateKey();
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.generateKey();
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Good case
    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSw());
    byte[] keyUID = response.getData();

    response = cmdSet.exportCurrentKey(true);
    assertEquals(0x9000, response.getSw());
    byte[] pubKey = response.getData();

    verifyKeyUID(keyUID, Arrays.copyOfRange(pubKey, 4, pubKey.length));
  }

  @Test
  @DisplayName("DERIVE KEY command")
  void deriveKeyTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x00});
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN is not verified
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x00});
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    if (cmdSet.getApplicationInfo().hasKeyManagementCapability()) {
      // Condition violation: keyset is not extended
      response = cmdSet.loadKey(keyPair);
      assertEquals(0x9000, response.getSw());
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x00});
      assertEquals(0x6985, response.getSw());

      response = cmdSet.loadKey(keyPair, false, chainCode);
      assertEquals(0x9000, response.getSw());
    }

    // Wrong data format
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00});
    assertEquals(0x6A80, response.getSw());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00});
    assertEquals(0x6A80, response.getSw());

    // Correct
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01});
    assertEquals(0x9000, response.getSw());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1});

    // 3 levels with hardened key
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01, (byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    assertEquals(0x9000, response.getSw());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 2});

    // From parent
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x03}, KeycardApplet.DERIVE_P1_SOURCE_PARENT);
    assertEquals(0x9000, response.getSw());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 3});

    // Reset master key
    response = cmdSet.deriveKey(new byte[0]);
    assertEquals(0x9000, response.getSw());
    verifyKeyDerivation(keyPair, chainCode, new int[0]);

    // Try parent when none available
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x03}, KeycardApplet.DERIVE_P1_SOURCE_PARENT);
    assertEquals(0x6B00, response.getSw());

    // 3 levels with hardened key using separate commands
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x01}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSw());
    response = cmdSet.deriveKey(new byte[]{(byte) 0x80, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_CURRENT);
    assertEquals(0x9000, response.getSw());
    response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x02}, KeycardApplet.DERIVE_P1_SOURCE_CURRENT);
    assertEquals(0x9000, response.getSw());
    verifyKeyDerivation(keyPair, chainCode, new int[]{1, 0x80000000, 2});

    // Reset master key
    response = cmdSet.deriveKey(new byte[0]);
    assertEquals(0x9000, response.getSw());
    verifyKeyDerivation(keyPair, chainCode, new int[0]);
  }

  @Test
  @DisplayName("SIGN command")
  void signTest() throws Exception {
    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.sign(hash);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.sign(hash);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (!cmdSet.getApplicationInfo().hasMasterKey()) {
      response = cmdSet.generateKey();
      assertEquals(0x9000, response.getSw());
    }

    // Wrong Data length
    response = cmdSet.sign(data);
    assertEquals(0x6A80, response.getSw());

    // Correctly sign a precomputed hash
    response = cmdSet.sign(hash);
    verifySignResp(data, response);

    //TODO: Integrate in SDK!
    // START SCHNORR
    APDUCommand sign = secureChannel.protectedCommand(0x80, 0xC0, 0x00, 0x01, hash);
    long time = System.currentTimeMillis();
    response = secureChannel.transmit(sdkChannel, sign);
    System.out.print("Schnorr time: ");
    System.out.println(System.currentTimeMillis() - time);
    response.checkOK();

    verifySchnorr(hash, response.getData());
    // END SCHNORR

    // Sign and derive
    String currentPath = new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData()).toString();
    String updatedPath = new KeyPath(currentPath + "/2").toString();
    response = cmdSet.signWithPath(hash, updatedPath, false);
    verifySignResp(data, response);
    assertEquals(currentPath, new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData()).toString());
    response = cmdSet.signWithPath(hash, updatedPath, true);
    verifySignResp(data, response);
    assertEquals(updatedPath, new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData()).toString());

    // Sign with PINless
    String pinlessPath = currentPath + "/3";
    response = cmdSet.setPinlessPath(pinlessPath);
    assertEquals(0x9000, response.getSw());

    // No secure channel or PIN auth
    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());

    response = cmdSet.signPinless(hash);
    verifySignResp(data, response);

    // With secure channel
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
      response = cmdSet.signPinless(hash);
      verifySignResp(data, response);
    }

    // No pinless path
    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.resetPinlessPath();
    assertEquals(0x9000, response.getSw());

    response = cmdSet.signPinless(hash);
    assertEquals(0x6A88, response.getSw());
  }

  private void verifySchnorr(byte[] m, byte[] sig) throws Exception {
    byte[] p = extractPublicKeyFromSignature(sig);
    byte[] rawSig = extractSignature(sig);

    byte[] r = Arrays.copyOfRange(rawSig, 2, 67);
    byte[] rawS = Arrays.copyOfRange(rawSig, 67, rawSig.length);

    System.out.println("p = " + Hex.toHexString(p));
    System.out.println("r = " + Hex.toHexString(r));
    System.out.println("s = " + Hex.toHexString(rawS));

    MessageDigest dg = MessageDigest.getInstance("SHA256");
    dg.update(r);
    dg.update(p);
    dg.update(m);
    BigInteger e = new BigInteger(1, dg.digest());

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPoint P = ecSpec.getCurve().decodePoint(p);
    ECPoint G = ecSpec.getG();

    BigInteger s = new BigInteger(1, rawS);

    ECPoint R = G.multiply(s).subtract(P.multiply(e));
    System.out.println("R = " + Hex.toHexString(R.getEncoded(false)));
    assertTrue(R.equals(ecSpec.getCurve().decodePoint(r)));
  }

  private void verifySignResp(byte[] data, APDUResponse response) throws Exception {
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    assertEquals(0x9000, response.getSw());
    byte[] sig = response.getData();
    byte[] keyData = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(keyData), ecSpec);
    ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

    signature.initVerify(cardKey);
    assertEquals((SecureChannel.SC_KEY_LENGTH * 2 / 8) + 1, keyData.length);
    signature.update(data);
    assertTrue(signature.verify(sig));
    assertFalse(isMalleable(sig));
  }

  @Test
  @DisplayName("SET PINLESS PATH command")
  @Capabilities("credentialsManagement") // The current test is not adapted to run automatically on devices without credentials management, since the tester must know what button to press
  void setPinlessPathTest() throws Exception {
    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);

    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.setPinlessPath(new byte[]{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02});
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.setPinlessPath(new byte[]{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02});
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (!cmdSet.getApplicationInfo().hasMasterKey()) {
      response = cmdSet.loadKey(keyPair, false, chainCode);
      assertEquals(0x9000, response.getSw());
    }

    // Wrong data
    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00});
    assertEquals(0x6a80, response.getSw());
    response = cmdSet.setPinlessPath(new byte[(KeycardApplet.KEY_PATH_MAX_DEPTH + 1)* 4]);
    assertEquals(0x6a80, response.getSw());

    // Correct
    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02});
    assertEquals(0x9000, response.getSw());

    // Verify that only PINless path can be used without PIN
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSw());

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSw());
    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02}, KeycardApplet.DERIVE_P1_SOURCE_CURRENT);
    assertEquals(0x9000, response.getSw());

    resetAndSelectAndOpenSC();

    response = cmdSet.sign(hash);
    assertEquals(0x9000, response.getSw());

    // Verify changing path
    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.setPinlessPath(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01});
    assertEquals(0x9000, response.getSw());
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSw());


    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSw());
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash);
    assertEquals(0x9000, response.getSw());

    // Reset
    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.setPinlessPath(new byte[] {});
    assertEquals(0x9000, response.getSw());
    resetAndSelectAndOpenSC();
    response = cmdSet.sign(hash);
    assertEquals(0x6985, response.getSw());

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.deriveKey(new byte[]{0x00, 0x00, 0x00, 0x02}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
      assertEquals(0x6985, response.getSw());
    }
  }

  @Test
  @DisplayName("EXPORT KEY command")
  void exportKey() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.exportCurrentKey(true);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.exportCurrentKey(true);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (cmdSet.getApplicationInfo().hasKeyManagementCapability()) {
      response = cmdSet.loadKey(keyPair, false, chainCode);
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.deriveKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSw());

    // Security condition violation: current key is not exportable
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x6985, response.getSw());

    response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2c, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSw());
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x6985, response.getSw());

    response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSw());
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x6985, response.getSw());

    // Export current public key
    response = cmdSet.exportCurrentKey(true);
    assertEquals(0x9000, response.getSw());
    byte[] keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000 }, true, false);

    // Derive & Make current
    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER,true,false);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000, 0x00000000 }, false, false);

    // Derive without making current
    response = cmdSet.exportKey(new byte[] {(byte) 0x00, 0x00, 0x00, 0x01}, KeycardApplet.DERIVE_P1_SOURCE_PARENT, false,false);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000, 0x00000001 }, false, true);
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, response.getData());

    // Export current
    response = cmdSet.exportCurrentKey(false);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000, 0x00000000 }, false, false);

    // Reset
    response = cmdSet.deriveKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("STORE/GET DATA")
  void storeGetDataTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.storeData(new byte[20], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.storeData(new byte[20], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Data too long
    response = cmdSet.storeData(new byte[128], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x6A80, response.getSw());

    byte[] data = new byte[127];

    for (int i = 0; i < 127; i++) {
      data[i] = (byte) i;
    }

    // Correct data
    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_PUBLIC);

    assertEquals(0x9000, response.getSw());

    // Read data back with secure channel
    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(data, response.getData());

    // Empty data
    response = cmdSet.storeData(new byte[0], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());
    assertEquals(0, response.getData().length);

    // Shorter data
    data = Arrays.copyOf(data, 20);
    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());

    // GET DATA without Secure Channel
    cmdSet.select().checkOK();

    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(data, response.getData());

    if (cmdSet.getApplicationInfo().hasNDEFCapability()) {
      byte[] ndefData = {
              (byte) 0x00, (byte) 0x24, (byte) 0xd4, (byte) 0x0f, (byte) 0x12, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
              (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d,
              (byte) 0x3a, (byte) 0x70, (byte) 0x6b, (byte) 0x67, (byte) 0x69, (byte) 0x6d, (byte) 0x2e, (byte) 0x73,
              (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x75, (byte) 0x73, (byte) 0x2e, (byte) 0x65, (byte) 0x74,
              (byte) 0x68, (byte) 0x65, (byte) 0x72, (byte) 0x65, (byte) 0x75, (byte) 0x6d
      };

      // Security condition violation: SecureChannel not open
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();

      // Security condition violation: PIN not verified
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());

      // Good case.
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x9000, response.getSw());

      // Good case with no length.
      response = cmdSet.setNDEF(Arrays.copyOfRange(ndefData, 2, ndefData.length));
      assertEquals(0x9000, response.getSw());
    }

    data[0] = (byte) 0xAA;

    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_CASH);
    assertEquals(0x9000, response.getSw());

    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());
    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    assertArrayEquals(data, info.getPubData());
  }

  @Test
  @DisplayName("Test the Cash applet")
  void cashTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    APDUResponse response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());

    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    assertTrue(info.getAppVersion() > 0);

    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);

    response = cashCmdSet.sign(hash);
    verifySignResp(data, response);

    //TODO: Integrate in SDK!
    // START SCHNORR
    APDUCommand sign = new APDUCommand(0x80, 0xC0, 0x00, 0x01, hash);
    long time = System.currentTimeMillis();
    response = sdkChannel.send(sign);
    System.out.print("Schnorr time: ");
    System.out.println(System.currentTimeMillis() - time);
    response.checkOK();

    verifySchnorr(hash, response.getData());
    // END SCHNORR
  }

  @Test
  @DisplayName("Mnemonic load and derivation")
  @Tag("manual")
  void mnemonicTest() throws Exception {
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    byte[] seed = Mnemonic.toBinarySeed("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will", "");
    response = cmdSet.loadKey(seed);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.exportCurrentKey(true);
    assertEquals(0x9000, response.getSw());

    BIP32KeyPair pubKey = BIP32KeyPair.fromTLV(response.getData());
    assertEquals("04cc620f846055ed43995391ca5e490c52251ea40453f64a0515bef84c24a653a7c4e02b9de56f66d9ee58dc6b591b534f5a20c0550b2c33a086b90b866cf70799", Hex.toHexString(pubKey.getPublicKey()));

    response = cmdSet.exportKey("m/43'/60'/1581'/0'/0", false, true);
    assertEquals(0x9000, response.getSw());

    pubKey = BIP32KeyPair.fromTLV(response.getData());
    assertEquals("04e7370d118461e1ab01f3e86e88c4b0c7b92cecb79c5e320cef73dda912f173beae74df15090b6405a274963c054cdfe6ac7843a302c260390d1fe776008f310e", Hex.toHexString(pubKey.getPublicKey()));
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
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());
    response = cmdSet.loadKey(wallet1.getEcKeyPair());
    assertEquals(0x9000, response.getSw());

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
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSw());

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] { (byte) 0x80, 0x00, 0x00, 0x2C, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
      deriveAccount += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSw());
    }

    deriveAccount /= SAMPLE_COUNT;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {0x00, 0x00, 0x00, (byte) i}, KeycardApplet.DERIVE_P1_SOURCE_PARENT);
      deriveParent += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSw());
    }

    deriveParent /= SAMPLE_COUNT;

    for (int i = 0; i < SAMPLE_COUNT; i++) {
      time = System.currentTimeMillis();
      response = cmdSet.deriveKey(new byte[] {(byte) 0x80, 0x00, 0x00, (byte) i}, KeycardApplet.DERIVE_P1_SOURCE_PARENT);
      deriveParentHardened += System.currentTimeMillis() - time;
      assertEquals(0x9000, response.getSw());
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
    assertEquals(KeycardApplet.TLV_SIGNATURE_TEMPLATE, sig[0]);
    assertEquals((byte) 0x81, sig[1]);
    assertEquals(KeycardApplet.TLV_PUB_KEY, sig[3]);

    return Arrays.copyOfRange(sig, 5, 5 + sig[4]);
  }

  private void reset() {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        simulator.reset();
        break;
      case TARGET_CARD:
        apduChannel.getCard().getATR();
        break;
      default:
        break;
    }
  }

  private void resetAndSelectAndOpenSC() throws Exception {
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      reset();
      cmdSet.select();
      cmdSet.autoOpenSecureChannel();
    }
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
    byte[] hash = sha256(new byte[8]);
    APDUResponse resp = cmdSet.sign(hash);
    assertEquals(0x9000, resp.getSw());
    byte[] sig = resp.getData();
    byte[] publicKey = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);

    if (cmdSet.getApplicationInfo().hasKeyManagementCapability()) {
      DeterministicKey key = deriveKey(keyPair, chainCode, path);

      assertTrue(key.verify(hash, sig));
      assertArrayEquals(key.getPubKeyPoint().getEncoded(false), publicKey);
    } else {
      Signature signature = Signature.getInstance("SHA256withECDSA", "BC");

      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(publicKey), ecSpec);
      ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

      signature.initVerify(cardKey);
      signature.update(new byte[8]);
      assertTrue(signature.verify(sig));
    }

    resp = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_KEY_PATH);
    assertEquals(0x9000, resp.getSw());
    byte[] rawPath = resp.getData();

    assertEquals(path.length * 4, rawPath.length);

    for (int i = 0; i < path.length; i++) {
      int k = path[i];
      int k1 = (rawPath[i * 4] << 24) | (rawPath[(i * 4) + 1] << 16) | (rawPath[(i * 4) + 2] << 8) | rawPath[(i * 4) + 3];
      assertEquals(k, k1);
    }
  }

  private void verifyExportedKey(byte[] keyTemplate, KeyPair keyPair, byte[] chainCode, int[] path, boolean publicOnly, boolean noPubKey) {
    if (!cmdSet.getApplicationInfo().hasKeyManagementCapability()) {
      return;
    }

    ECKey key = deriveKey(keyPair, chainCode, path).decompress();
    assertEquals(KeycardApplet.TLV_KEY_TEMPLATE, keyTemplate[0]);
    int pubKeyLen = 0;

    if (!noPubKey) {
      assertEquals(KeycardApplet.TLV_PUB_KEY, keyTemplate[2]);
      byte[] pubKey = Arrays.copyOfRange(keyTemplate, 4, 4 + keyTemplate[3]);
      assertArrayEquals(key.getPubKey(), pubKey);
      pubKeyLen = 2 + pubKey.length;
    }

    if (publicOnly) {
      assertEquals(pubKeyLen, keyTemplate[1]);
      assertEquals(pubKeyLen + 2, keyTemplate.length);
    } else {
      assertEquals(KeycardApplet.TLV_PRIV_KEY, keyTemplate[2 + pubKeyLen]);
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

    APDUResponse response = cmdSet.sign(messageHash);
    assertEquals(0x9000, response.getSw());
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

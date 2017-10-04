package im.status.wallet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.*;

import javax.smartcardio.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Test the Wallet Applet")
public class WalletAppletTest {
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;

  private SecureChannelSession secureChannel;
  private WalletAppletCommandSet cmdSet;

  @BeforeAll
  static void initAll() throws CardException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    TerminalFactory tf = TerminalFactory.getDefault();

    for (CardTerminal t : tf.terminals().list()) {
      if (t.isCardPresent()) {
        cardTerminal = t;
        break;
      }
    }

    Card apduCard = cardTerminal.connect("T=1");
    apduChannel = apduCard.getBasicChannel();
  }

  @BeforeEach
  void init() throws CardException {
    apduChannel.getCard().getATR();
    cmdSet = new WalletAppletCommandSet(apduChannel);
    byte[] keyData = cmdSet.select().getData();
    secureChannel = new SecureChannelSession(keyData);
    cmdSet.setSecureChannel(secureChannel);
  }

  @AfterEach
  void tearDown() {
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
    assertEquals(0x04, data[0]);
    assertEquals((SecureChannel.SC_KEY_LENGTH * 2 / 8) + 1, data.length);
  }

  @Test
  @DisplayName("OPEN SECURE CHANNEL command")
  void openSecureChannelTest() throws CardException {
    ResponseAPDU response = cmdSet.openSecureChannel();
    assertEquals(0x9000, response.getSW());
    assertEquals(SecureChannel.SC_SECRET_LENGTH, response.getData().length);
  }

  @Test
  @DisplayName("VERIFY PIN command")
  void verifyPinTest() throws CardException {
    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x6985, response.getSW());

    cmdSet.openSecureChannel();

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

    cmdSet.openSecureChannel();

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
    apduChannel.getCard().getATR();
    cmdSet.select();
    cmdSet.openSecureChannel();

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

    cmdSet.openSecureChannel();

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
    apduChannel.getCard().getATR();
    cmdSet.select();
    cmdSet.openSecureChannel();

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

    cmdSet.openSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    // Wrong key type
    response = cmdSet.loadKey(new byte[] { (byte) 0xAA, 0x02, (byte) 0x80, 0x00}, (byte) 0x00);
    assertEquals(0x6A86, response.getSW());

    // Wrong data (wrong template, missing private key, invalid keys)
    response = cmdSet.loadKey(new byte[] { (byte) 0xAA, 0x02, (byte) 0x80, 0x00}, WalletApplet.LOAD_KEY_EC);
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.loadKey(new byte[] { (byte) 0xA1, 0x02, (byte) 0x80, 0x00}, WalletApplet.LOAD_KEY_EC);
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.loadKey(new byte[] { (byte) 0xA1, 0x06, (byte) 0x80, 0x01, 0x01, (byte) 0x81, 0x01, 0x02}, WalletApplet.LOAD_KEY_EC);
    assertEquals(0x6A80, response.getSW());

    // Correct LOAD KEY
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());

    keyPair = g.generateKeyPair();

    // Check replacing keys
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("SIGN command")
  void signTest() throws Exception {
    Random r = new Random();
    byte[] data = new byte[SecureChannelSession.PAYLOAD_MAX_SIZE];
    byte[] smallData = Arrays.copyOf(data, 20);
    r.nextBytes(data);

    // Security condition violation: SecureChannel not open
    ResponseAPDU response = cmdSet.sign(smallData, true, true);
    assertEquals(0x6985, response.getSW());

    cmdSet.openSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.sign(smallData, true, true);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = keypairGenerator().generateKeyPair();
    Signature signature = Signature.getInstance("ECDSAwithSHA256", "BC");
    signature.initVerify(keyPair.getPublic());

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());

    // Wrong P2: no active signing session but first block bit not set
    response = cmdSet.sign(data, false, false);
    assertEquals(0x6A86, response.getSW());

    response = cmdSet.sign(data, false, true);
    assertEquals(0x6A86, response.getSW());

    // Correctly sign 1 block (P2: 0x81)
    response = cmdSet.sign(smallData, true, true);
    assertEquals(0x9000, response.getSW());
    byte[] sig = secureChannel.decryptAPDU(response.getData());
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Correctly sign 2 blocks (P2: 0x01, 0x81)
    response = cmdSet.sign(data, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, false, true);
    assertEquals(0x9000, response.getSW());
    sig = secureChannel.decryptAPDU(response.getData());
    signature.update(data);
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Correctly sign 3 blocks (P2: 0x01, 0x00, 0x80)
    response = cmdSet.sign(data, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(data, false, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, false, true);
    assertEquals(0x9000, response.getSW());
    sig = secureChannel.decryptAPDU(response.getData());
    signature.update(data);
    signature.update(data);
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Re-start signing session by sending new first block
    response = cmdSet.sign(data, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, true, true);
    assertEquals(0x9000, response.getSW());
    sig = secureChannel.decryptAPDU(response.getData());
    signature.update(smallData);
    assertTrue(signature.verify(sig));

    // Abort signing session by loading new keys
    response = cmdSet.sign(data, true, false);
    assertEquals(0x9000, response.getSW());
    keyPair = keypairGenerator().generateKeyPair();
    signature.initVerify(keyPair.getPublic());
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, false, true);
    assertEquals(0x6A86, response.getSW());

    // Signing session is aborted on reselection
    response = cmdSet.sign(data, true, false);
    assertEquals(0x9000, response.getSW());
    apduChannel.getCard().getATR();
    cmdSet.select();
    cmdSet.openSecureChannel();
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, false, true);
    assertEquals(0x6A86, response.getSW());

    // Signing session can be resumed if other commands are sent
    response = cmdSet.sign(data, true, false);
    assertEquals(0x9000, response.getSW());
    response = cmdSet.changePIN("000000");
    assertEquals(0x9000, response.getSW());
    response = cmdSet.sign(smallData, false, true);
    assertEquals(0x9000, response.getSW());
    sig = secureChannel.decryptAPDU(response.getData());
    signature.update(data);
    signature.update(smallData);
    assertTrue(signature.verify(sig));
  }

  private KeyPairGenerator keypairGenerator() throws Exception {
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ecSpec);

    return g;
  }
}

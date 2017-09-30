package im.status.wallet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.*;

import javax.smartcardio.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
    ResponseAPDU response = cmdSet.verifyPIN("000000");
    assertEquals(0x6985, response.getSW());

    cmdSet.openSecureChannel();

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSW());

    response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("CHANGE PIN command")
  void changePinTest() throws CardException {
    ResponseAPDU response = cmdSet.changePIN("123456");
    assertEquals(0x6985, response.getSW());

    cmdSet.openSecureChannel();

    response = cmdSet.changePIN("123456");
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN("123456");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN("654321");
    assertEquals(0x9000, response.getSW());

    apduChannel.getCard().getATR();
    cmdSet.select();
    cmdSet.openSecureChannel();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN("654a21");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN("54321");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN("7654321");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.changePIN("000000");
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("UNBLOCK PIN command")
  void unblockPinTest() throws CardException {
    ResponseAPDU response = cmdSet.changePIN("123456");
    assertEquals(0x6985, response.getSW());

    cmdSet.openSecureChannel();

    response = cmdSet.unblockPIN("123456789012", "000000");
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSW());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSW());

    response = cmdSet.unblockPIN("12345678901", "000000");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.unblockPIN("1234567890123", "000000");
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.unblockPIN("123456789010", "000000");
    assertEquals(0x63C4, response.getSW());

    response = cmdSet.unblockPIN("123456789012", "654321");
    assertEquals(0x9000, response.getSW());

    apduChannel.getCard().getATR();
    cmdSet.select();
    cmdSet.openSecureChannel();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.changePIN("000000");
    assertEquals(0x9000, response.getSW());
  }

  @Test
  @DisplayName("LOAD KEY command")
  void loadKeyTest() throws Exception {
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ecSpec);

    KeyPair keyPair = g.generateKeyPair();

    ResponseAPDU response = cmdSet.loadKey(keyPair);
    assertEquals(0x6985, response.getSW());

    cmdSet.openSecureChannel();

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x6985, response.getSW());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSW());

    response = cmdSet.loadKey(new byte[] { (byte) 0xAA, 0x02, (byte) 0x80, 0x00}, (byte) 0x00);
    assertEquals(0x6A86, response.getSW());

    response = cmdSet.loadKey(new byte[] { (byte) 0xAA, 0x02, (byte) 0x80, 0x00}, WalletApplet.LOAD_KEY_EC);
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.loadKey(new byte[] { (byte) 0xA1, 0x02, (byte) 0x80, 0x00}, WalletApplet.LOAD_KEY_EC);
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.loadKey(new byte[] { (byte) 0xA1, 0x06, (byte) 0x80, 0x01, 0x01, (byte) 0x81, 0x01, 0x02}, WalletApplet.LOAD_KEY_EC);
    assertEquals(0x6A80, response.getSW());

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());

    keyPair = g.generateKeyPair();

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSW());
  }
}

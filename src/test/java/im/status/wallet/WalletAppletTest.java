package im.status.wallet;

import org.junit.jupiter.api.*;

import javax.smartcardio.*;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Test the Wallet Applet")
public class WalletAppletTest {
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;

  private SecureChannelSession secureChannel;

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
    byte[] keyData = WalletAppletCommandSet.select(apduChannel).getData();
    secureChannel = new SecureChannelSession(keyData);
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
    ResponseAPDU response = WalletAppletCommandSet.select(apduChannel);
    assertEquals(0x9000, response.getSW());
    byte[] data = response.getData();
    assertEquals(0x04, data[0]);
    assertEquals((SecureChannel.SC_KEY_SIZE * 2 / 8) + 1, data.length);
  }

  @Test
  @DisplayName("OPEN SECURE CHANNEL command")
  void openSecureChannelTest() throws CardException {
    ResponseAPDU response = secureChannel.openSecureChannel(apduChannel);
    assertEquals(0x9000, response.getSW());
    assertEquals(SecureChannel.SC_SECRET_LENGTH, response.getData().length);
  }

  @Test
  @DisplayName("VERIFY PIN command")
  void verifyPinTest() throws CardException {
    ResponseAPDU response = WalletAppletCommandSet.verifyPIN(apduChannel, "123456");
    assertEquals(0x63C2, response.getSW());

    response = WalletAppletCommandSet.verifyPIN(apduChannel, "000000");
    assertEquals(0x9000, response.getSW());

    response = WalletAppletCommandSet.verifyPIN(apduChannel, "123456");
    assertEquals(0x63C2, response.getSW());

    response = WalletAppletCommandSet.verifyPIN(apduChannel, "123456");
    assertEquals(0x63C1, response.getSW());

    response = WalletAppletCommandSet.verifyPIN(apduChannel, "123456");
    assertEquals(0x63C0, response.getSW());

    response = WalletAppletCommandSet.verifyPIN(apduChannel, "000000");
    assertEquals(0x63C0, response.getSW());

    //TODO: Unblock PIN to make the test non-destructive
  }
}

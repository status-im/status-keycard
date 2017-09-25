package im.status.wallet;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;

import javax.smartcardio.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Test the Wallet Applet")
public class WalletAppletTest {
  private static final String APPLET_AID = "53746174757357616C6C6574417070";
  private static final byte[] APPLET_AID_BYTES = Hex.decode(APPLET_AID);

  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;

  @BeforeAll
  static void initAll() throws CardException {
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
    WalletAppletCommandSet.select(apduChannel);
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
    //TODO: as soon as secure channel is implemented, check that a public key is returned.

    ResponseAPDU response = WalletAppletCommandSet.select(apduChannel);
    assertEquals(0x9000, response.getSW());
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

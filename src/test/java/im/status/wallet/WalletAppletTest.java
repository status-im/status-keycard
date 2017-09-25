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
  void init() {
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
}

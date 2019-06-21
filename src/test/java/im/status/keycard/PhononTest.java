package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import im.status.keycard.KeycardApplet;
import im.status.keycard.applet.*;
import im.status.keycard.desktop.LedgerUSBManager;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardListener;
import im.status.keycard.Crypto;
import javacard.framework.AID;
import javacard.framework.ISO7816;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
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

import org.bouncycastle.jce.interfaces.ECPublicKey;

import javax.smartcardio.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import static org.apache.commons.codec.digest.DigestUtils.sha256;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Test Phonon Functionality")
public class PhononTest {
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

    //=================================================================
    // SETUP
    //=================================================================

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
        AID appletAID = AIDUtil.create(Identifiers.getKeycardInstanceAID());
        simulator.installApplet(appletAID, KeycardApplet.class);
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
        byte[] data = cmdSet.select().checkOK().getData();

        initCapabilities(cmdSet.getApplicationInfo());

        sharedSecret = cmdSet.pairingPasswordToSecret(System.getProperty("im.status.keycard.test.pairing", "KeycardTest"));

        if (!cmdSet.getApplicationInfo().isInitializedCard()) {
        assertEquals(0x9000, cmdSet.init("000000", "123456789012", sharedSecret).getSw());
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

    //=================================================================
    // HELPERS
    //=================================================================

    private void resetAndSelectAndOpenSC() throws Exception {
        if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
            reset();
            cmdSet.select();
            cmdSet.autoOpenSecureChannel();
        }
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

    //=================================================================
    // TESTS
    //=================================================================

    @Test
    @DisplayName("SELECT command")
    void selectTest() throws Exception {
        APDUResponse response = cmdSet.select();
        assertEquals(0x9000, response.getSw());
        byte[] data = response.getData();

        assertTrue(new ApplicationInfo(data).isInitializedCard());
    }

    //--------------------------------
    // Setup
    //--------------------------------
    @Test
    @DisplayName("Add network descriptors")
    void addNetworkDescriptors() throws Exception {
        APDUResponse response = cmdSet.select();
        assertEquals(0x9000, response.getSw());
        byte[] data = response.getData();

        assertTrue(new ApplicationInfo(data).isInitializedCard());
    }
    
    //--------------------------------
    // Deposits
    //--------------------------------

   

}
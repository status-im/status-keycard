package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import im.status.keycard.KeycardApplet;
import im.status.keycard.PhononNetwork;
import im.status.keycard.applet.*;
import im.status.keycard.desktop.LedgerUSBManager;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardListener;
import im.status.keycard.Crypto;
import javacard.framework.AID;
import javacard.framework.Util;
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

    private static byte[] emptyData = {};

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

    private byte[] buildPhonon(byte networkId, byte assetId, short amount, byte decimals, byte[] extraData) {
        byte[] p = new byte[5 + extraData.length]; // Serialized phonon length less the pubkey
        short off = 0;
        p[off] = networkId; off++;
        p[off] = assetId; off++;
        byte[] a = PhononNetwork.shortToBytes(amount);
        p[off] = a[0]; off++;
        p[off] = a[1]; off++;
        p[off] = decimals; off++;
        for (short i = 0; i < extraData.length; i++) {
            p[i + off] = extraData[i];
        }
        return p;
    }

    private void validatePhonon(byte networkId, byte assetId, short amount, byte decimals, byte[] extraData, byte[] p) {
        assertEquals(KeycardApplet.TLV_PHONON, p[0]);
        assertEquals(Phonon.SERIALIZED_PHONON_LEN, p[1]);
        assertEquals(networkId, p[2]);
        assertEquals(assetId, p[3]);
        short pAmount = PhononNetwork.bytesToShort(p[4], p[5]);
        assertEquals(pAmount, amount);
        assertEquals(decimals, p[6]);
        for (short i = 0; i < 33; i++) {
            assertEquals(p[7 + i], extraData[i]);
        }
    }

    private void validateNewSalt(byte[] d) {
        assertEquals(d[0], KeycardApplet.TLV_PHONON_NEW_SALT);
        assertEquals(d[1], KeycardApplet.TLV_SHORT);
        assertEquals(d[2], (byte) 2);
        assertEquals(d[5], KeycardApplet.TLV_INT);
        assertEquals(d[6], (byte) 4);
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
    @DisplayName("Test network descriptors")
    void networkDescriptorsTest() throws Exception {
        APDUResponse response;
        Random random = new Random();
        byte[] d;
        byte slot = 0x00;
        byte[] networkData;
        
        // Fail to add a short descriptor
        d = new byte[31];
        random.nextBytes(d);
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_SET_NETWORK_DESCRIPTOR, slot, (byte) 0, d);
        assertEquals(ISO7816.SW_DATA_INVALID, response.getSw());
        
        // Fail to add a long descriptor
        d = new byte[33];
        random.nextBytes(d);
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_SET_NETWORK_DESCRIPTOR, slot, (byte) 0, d);
        assertEquals(ISO7816.SW_DATA_INVALID, response.getSw());
        
        // Fail to add a descriptor to an index > 4
        d = new byte[32];
        random.nextBytes(d);
        slot = 0x05;
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_SET_NETWORK_DESCRIPTOR, slot, (byte) 0, d);
        assertEquals(ISO7816.SW_DATA_INVALID, response.getSw());

        // Add a descriptor of proper length
        slot = 0x04;
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_SET_NETWORK_DESCRIPTOR, slot, (byte) 0, d);
        assertEquals(0x9000, response.getSw());

        // Fail to get data at slot >4
        slot = 0x05;
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_GET_NETWORK_DESCRIPTOR, slot, (byte) 0,  emptyData);
        assertEquals(ISO7816.SW_DATA_INVALID, response.getSw());

        // Get the data at slot 0 (should be empty)
        slot = 0x01;
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_GET_NETWORK_DESCRIPTOR, slot, (byte) 0,  emptyData);
        assertEquals(0x9000, response.getSw());
        networkData = response.getData();
        assertEquals(networkData[0], KeycardApplet.TLV_PHONON_NETWORK_DESCRIPTOR);
        assertEquals(networkData[1], PhononNetwork.NETWORK_DESCRIPTOR_LEN);
        for (int i = 2; i < networkData.length; i++) {
            assertEquals(0x00, networkData[i]);
        }

        // Get the data at slot 4 (should be equal to `d`)
        slot = 0x04;
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_GET_NETWORK_DESCRIPTOR, slot, (byte) 0,  emptyData);
        assertEquals(0x9000, response.getSw());
        networkData = response.getData();
        assertEquals(networkData[0], KeycardApplet.TLV_PHONON_NETWORK_DESCRIPTOR);
        assertEquals(networkData[1], PhononNetwork.NETWORK_DESCRIPTOR_LEN);
        for (int i = 2; i < networkData.length; i++) {
            assertEquals(d[i - 2], networkData[i]);
        }
    }

    //--------------------------------
    // Deposits
    //--------------------------------
    
    @Test
    @DisplayName("Test network descriptors")
    void depositTest() throws Exception {
        APDUResponse response;
        Random random = new Random();
        byte[] p;
        byte[] extraData = new byte[33];
        byte[] d;
        byte networkId = 4;
        byte assetId = 13;
        byte decimals = 1;
        short amount = 1000;
        random.nextBytes(extraData);

        // Get the deposit nonce (it should be zero)
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_GET_DEPOSIT_NONCE, (byte) 0, (byte) 0, emptyData);
        assertEquals(0x9000, response.getSw());
        d = response.getData();
        short nonce = PhononNetwork.bytesToShort(d[2], d[3]);
        assertEquals((short) 0, nonce);

        // Fail to make a deposit with correct params to nonce equal deposit nonce
        p = buildPhonon(networkId, assetId, amount, decimals, extraData);
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_DEPOSIT, (byte) 0, (byte) 0, p);
        assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, response.getSw());

        // Fail to make deposit with bad fields
        byte[] badExtraData = {1, 2, 3, 4, 5};
        byte[] badPhonon = buildPhonon((byte) 0, (byte) 0, (short) 1000, (byte) 1, badExtraData);
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_DEPOSIT, (byte) 0, (byte) 0x01, badPhonon);
        assertEquals(ISO7816.SW_WRONG_DATA, response.getSw());
        // NetworkId > 4
        badPhonon = buildPhonon((byte) 5, (byte) 0, (short) 1000, (byte) 1, extraData);
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_DEPOSIT, (byte) 0, (byte) 0x01, badPhonon);
        assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, response.getSw());

        // Ensure deposit nonce is still zero
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_GET_DEPOSIT_NONCE, (byte) 0, (byte) 0, emptyData);
        assertEquals(0x9000, response.getSw());
        byte[] newNonceData = response.getData();
        assertEquals(nonce, PhononNetwork.bytesToShort(newNonceData[2], newNonceData[3]));

        // Ensure there is no phonon at the first slot
        response = cmdSet.sendCommand(KeycardApplet.INS_GET_PHONON, (byte) 0, (byte) 0, emptyData);
        assertEquals(0x9000, response.getSw());
        byte[] phononAt = response.getData();
        assertEquals(KeycardApplet.TLV_PHONON, phononAt[0]);
        assertEquals(0, phononAt[1]);

        // Deposit with correct params
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_DEPOSIT, (byte) 0, (byte) 1, p);
        assertEquals(0x9000, response.getSw());
        d = response.getData();
        short depositIndex = PhononNetwork.bytesToShort(d[2], d[3]);
        assertEquals((short) 0, depositIndex);

        // Ensure deposit nonce has incremented
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_GET_DEPOSIT_NONCE, (byte) 0, (byte) 0, emptyData);
        assertEquals(0x9000, response.getSw());
        d = response.getData();
        short newNonce = PhononNetwork.bytesToShort(d[2], d[3]);
        assertEquals(newNonce, nonce+1);

        // Ensure there is a phonon in the first slot
        response = cmdSet.sendCommand(KeycardApplet.INS_GET_PHONON, (byte) 0, (byte) 0, emptyData);
        assertEquals(0x9000, response.getSw());
        d = response.getData();
        validatePhonon(networkId, assetId, amount, decimals, extraData, d);
    }

    @Test
    @DisplayName("Receive a phonon command")
    void receiveTest() throws Exception {
        // Get a salt 
        APDUResponse response;
        byte[] data;
        // Timestamps aren't enforced at the card level. Here's a static, dummy one.
        byte[] timestamp = { (byte) 0x5d, (byte) 0x12, (byte) 0x8a, (byte) 0xab }; // 1561496235

        // Fail to begin with a 3 byte timestamp
        byte[] badTs = { (byte) 0x5d, (byte) 0x12, (byte) 0x8a };
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_NEW_SALT, (byte) 0, (byte) 0, badTs);
        assertEquals(ISO7816.SW_WRONG_DATA, response.getSw());

        // Fail to begin with a 5 byte timestamp
        byte[] badTs2 = { (byte) 0x5d, (byte) 0x12, (byte) 0x8a, (byte) 0xab, (byte) 0x01 };
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_NEW_SALT, (byte) 0, (byte) 0, badTs2);
        assertEquals(ISO7816.SW_WRONG_DATA, response.getSw());

        // Ensure we can load the full number of salts
        for (short i = 0; i < PhononNetwork.NUM_SALT_SLOTS; i++) {
            response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_NEW_SALT, (byte) 0, (byte) i, timestamp);
            assertEquals(0x9000, response.getSw());
            data = response.getData();
            System.out.println("data " + Arrays.toString(data));
            validateNewSalt(data);
        }

        // Fail to load a new salt
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_NEW_SALT, (byte) 0, (byte) 0, timestamp);
        assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, response.getSw());

        // Fail to remove a salt that is out of bounds
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_REMOVE_SALT, (byte) 0, (byte) 6, emptyData);
        assertEquals(ISO7816.SW_WRONG_DATA, response.getSw());

        // Get the 3rd salt and ensure it is non-null
        response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_GET_SALT, (byte) 0, (byte) 3, emptyData);
        assertEquals(0x9000, response.getSw());
        data = response.getData();
        System.out.println("salt" + Arrays.toString(data));

        // // Remove the 3rd salt
        // response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_REMOVE_SALT, (byte) 0, (byte) 3, emptyData);
        // assertEquals(0x9000, response.getSw());

        // // Fail to remove the 3rd salt again because it is empty
        // response = cmdSet.sendCommand(KeycardApplet.INS_PHONON_REMOVE_SALT, (byte) 0, (byte) 3, emptyData);
        // assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, response.getSw());
    }

}
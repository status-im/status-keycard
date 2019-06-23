package im.status.keycard;
import javacard.framework.*;

public class PhononNetwork {
    static final public byte NETWORK_DESCRIPTOR_LEN = 32;
    static final public byte EXTRA_DATA_LEN = 33;
    static final public byte NUM_PHONONS = 32;
    static final public byte NUM_NETWORK_SLOTS = 5;
    static final public short DEPOSIT_FAIL = 10000;

    private short depositNonce;
    private short[] salts;
    private short[] saltsTs;
    private Phonon[] phonons;
    private byte[] networks;

    PhononNetwork() {
        this.depositNonce = 0;              // Global nonce tracker to prevent replayed deposits
        this.phonons = new Phonon[NUM_PHONONS];       // Set of phonons
        this.salts = new short[5];          // Salt slots for receiving phonons
        this.saltsTs = new short[5];        // Corresponding timestamps for salts
        this.networks = new byte[NETWORK_DESCRIPTOR_LEN * NUM_NETWORK_SLOTS];   // 5x Network descriptors
    }


    //==========================================================================================================
    // PRIVATE HELPERS
    //==========================================================================================================    

    // Get the current deposit nonce
    public short getDepositNonce() {
        return this.depositNonce;
    }

    private short getNextPhononSlot() {
        for (short i = 0; i < NUM_PHONONS; i++) {
            if (phonons[i].amount == 0) {
                return i;
            }
        }
        return -1;
    }

    // Unpack a 37 byte serialized payload
    private Phonon unpackDeposit(short nonce, byte[] priv, byte[] d) {
        short off = 0;
        // byte 0
        byte networkId = d[off];
        // byte 1
        byte assetId = d[off++];
        // byte 2-3
        byte a1 = d[off++];
        byte a2 = d[off++];
        short amount = Util.makeShort(a1, a2);
        // byte 4
        byte decimals = d[off++];
        // byte 5-36
        byte[] extraData = new byte[EXTRA_DATA_LEN];
        Util.arrayCopy(d, off, extraData, (short) 0, EXTRA_DATA_LEN);
        Phonon p = new Phonon(networkId, assetId, priv, amount, decimals, extraData);
        return p;
    }

    //==========================================================================================================
    // PUBLIC GETTERS AND SETTERS
    //==========================================================================================================    

    // Add a 32 byte network descriptor. This must be 32 bytes and should be left-padded with zeros,
    // though the padding itself is not enforced here.
    public boolean setNetworkDescriptor(short i, byte[] d) {
        if (d.length != NETWORK_DESCRIPTOR_LEN || i < 0 || i > 4) {
            return false;
        }
        Util.arrayCopy(d, (short) 0, this.networks, (short) (i * NETWORK_DESCRIPTOR_LEN), NETWORK_DESCRIPTOR_LEN);
        return true;
    }

    // Get the network descriptor at slot `i`
    public byte[] getNetworkDescriptor(short i) {
        byte[] d = new byte[NETWORK_DESCRIPTOR_LEN];
        if (i >= 0 && i <= 4) {
            Util.arrayCopy(this.networks, (short) (i * NETWORK_DESCRIPTOR_LEN), d, (short) 0, NETWORK_DESCRIPTOR_LEN);
        }
        return d;
    }

    // Request a serialized phonon payload given an index.
    // This does *not* include the private key
    public byte[] getSerializedPhonon(short i) {
        return phonons[i].serialize();
    }

    //==========================================================================================================
    // DEPOSITS
    //==========================================================================================================

    public short deposit(short nonce, byte[] priv, byte[] payload) {
        // Ensure we are able to deposit at this nonce
        if (nonce <= this.depositNonce) {
            return DEPOSIT_FAIL;
        }
        // Ensure there is an available phonon slot
        short i = getNextPhononSlot();
        if (i < 0) {
            return DEPOSIT_FAIL;
        }
        // Ensure the payload is the correct length
        byte inLen = (byte) (payload.length + priv.length);
        if (inLen != Phonon.SERIALIZED_PHONON_LEN) {        
            return DEPOSIT_FAIL;
        }
        // Save the phonon
        Phonon p = unpackDeposit(nonce, priv, payload);
        phonons[i] = p;
        // Increment nonce and return phonon index
        this.depositNonce = nonce;
        return i;
    }


}
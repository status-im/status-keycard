package im.status.keycard;
import javacard.framework.*;

public class PhononNetwork {
    static final public byte NETWORK_DESCRIPTOR_LEN = 32;
    static final public byte INT_LEN = 4; // Number of bytes per integer
    static final public byte EXTRA_DATA_LEN = 33;
    static final public byte NUM_PHONON_SLOTS = 32;
    static final public byte NUM_NETWORK_SLOTS = 5;
    static final public byte NUM_SALT_SLOTS = 5;
    static final public short DEPOSIT_FAIL = 10000;
    static final public short NO_PHONON_SLOT = 10000;
    static final public short NO_SALT_SLOT = 10000;

    private short depositNonce;
    private byte[] salts;
    private byte[] saltsTs;
    private Phonon[] phonons;
    private byte[] networks;

    PhononNetwork() {
        this.depositNonce = 0;              // Global nonce tracker to prevent replayed deposits
        this.phonons = new Phonon[NUM_PHONON_SLOTS];       // Set of phonons
        this.salts = new byte[INT_LEN * NUM_SALT_SLOTS];          // Salt slots for receiving phonons
        this.saltsTs = new byte[INT_LEN * NUM_SALT_SLOTS];        // Corresponding timestamps for salts
        this.networks = new byte[NETWORK_DESCRIPTOR_LEN * NUM_NETWORK_SLOTS];   // 5x Network descriptors
    }


    //==========================================================================================================
    // PRIVATE HELPERS
    //==========================================================================================================    
    private short getNextSaltSlot() {
        for (short i = 0; i < NUM_SALT_SLOTS; i++) {
            if (saltIsEmpty(i) == true) { 
                return i;
            }
        }
        return NO_SALT_SLOT;
    }

    private short getNextPhononSlot() {
        for (short i = 0; i < NUM_PHONON_SLOTS; i++) {
            if (phonons[i] == null) {
                return i;
            }
        }
        return NO_PHONON_SLOT;
    }

    // Unpack a 37 byte serialized payload
    private Phonon unpackDeposit(short nonce, byte[] priv, byte[] d) {
        short off = 0;
        // byte 0
        byte networkId = d[off]; off++;
        // byte 1
        byte assetId = d[off]; off++; 
        // byte 2-3
        byte a1 = d[off]; off++;
        byte a2 = d[off]; off++;
        short amount = bytesToShort(a1, a2);
        // byte 4
        byte decimals = d[off]; off++;
        // byte 5-36
        byte[] extraData = new byte[EXTRA_DATA_LEN];
        Util.arrayCopy(d, off, extraData, (short) 0, EXTRA_DATA_LEN);
        Phonon p = new Phonon(networkId, assetId, priv, amount, decimals, extraData);
        return p;
    }

    //==========================================================================================================
    // PUBLIC HELPERS
    //==========================================================================================================    

    static public byte[] shortToBytes(short s) {
        byte[] b = new byte[2];
        b[0] = (byte) ((s >> 8) & 0xFF);
        b[1] = (byte) (s & 0xFF);
        return b;
    }

    static public short bytesToShort(byte a, byte b) {
        return (short)(((a & 0xFF) << 8) | (b & 0xFF));
    }

    //==========================================================================================================
    // PUBLIC GETTERS AND SETTERS
    //==========================================================================================================    

    // Get the current deposit nonce
    public short getDepositNonce() {
        return this.depositNonce;
    }

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
        if (phonons[i] != null) {
            return phonons[i].serialize();
        }
        byte[] r = {};
        return r;
    }

    public boolean saltIsEmpty(short i) {
        if (i >= NUM_SALT_SLOTS) {
            return false;
        }
        short si = (short) (i * INT_LEN);
        if (salts[si] == (byte) 0 && salts[(short) (si + 1)] == (byte) 0
            && salts[(short) (si + 2)] == (byte) 0 && salts[(short) (si + 3)] == (byte) 0) {
            return true;
        }
        return false;
    }


    //==========================================================================================================
    // DEPOSITS
    //==========================================================================================================

    // Determine whether we can deposit this phonon
    public boolean canDeposit(short nonce, byte[] priv, byte[] payload) {
        // Ensure we are able to deposit at this nonce
        if (nonce <= this.depositNonce) {
            return false;
        }
        // Ensure there is an available phonon slot
        if (getNextPhononSlot() == NO_PHONON_SLOT) {
            return false;
        }
        // Ensure the payload is the correct length
        byte inLen = (byte) (payload.length + priv.length);
        if (inLen != Phonon.SERIALIZED_DEPOSIT_LEN) {        
            return false;
        }
        // Verify that networkId is in bounds
        if (payload[0] >= NUM_NETWORK_SLOTS) {
            return false;
        }
        return true;
    }

    // Deposit the phonon
    public short deposit(short nonce, byte[] priv, byte[] payload) {
        short i = getNextPhononSlot();
        Phonon p = unpackDeposit(nonce, priv, payload);
        phonons[i] = p;
        this.depositNonce = nonce;
        return i;
    }

    //==========================================================================================================
    // RECEIVE
    //==========================================================================================================

    // Determine if we can start the receive process by generating a new salt and saving it
    public boolean canMakeNewSalt(byte[] salt, byte[] ts) {
        if (getNextSaltSlot() == NO_SALT_SLOT || salt.length != INT_LEN || ts.length != INT_LEN) {
            return false;
        }
        return true;
    }

    // Save the generated salt at the next available slot. This function will only be called
    // after `canReceive`, which ensures there is a salt slot available.
    public short newSalt(byte[] salt, byte[] ts) {
        short i = getNextSaltSlot();
        Util.arrayCopy(salt, (short) 0, this.salts, (short) (i * INT_LEN), INT_LEN);
        Util.arrayCopy(ts, (short) 0, this.saltsTs, (short) (i * INT_LEN), INT_LEN);
        return i;
    }

    public byte[] getSalt(short i) {
        byte[] s = new byte[4];
        Util.arrayCopyNonAtomic(this.salts, (byte) (i * INT_LEN), s, (byte) 0, INT_LEN);
        return s;
    }

    public void removeSalt(short i) {
        short j = (short) (i * 4);
        this.salts[j] = 0;
        this.saltsTs[j] = 0;
        this.salts[(short) (j + 1)] = 0;
        this.saltsTs[(short) (j + 1)] = 0;
        this.salts[(short) (j + 2)] = 0;
        this.saltsTs[(short) (j + 2)] = 0;
        this.salts[(short) (j + 3)] = 0;
        this.saltsTs[(short) (j + 3)] = 0;
        return;
    }
}
package im.status.keycard;
import javacard.security.*;
import javacardx.crypto.Cipher;
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

    // Unpack a 38 byte serialized payload
    private Phonon unpackPhonon(byte[] priv, byte[] d) {
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

    // Given a private and public key, generate the ECDH shared secret
    private static byte[] ecdhSharedSecret(Crypto crypto, KeyPair kp, byte[] pub) {
        byte[] secret = new byte[Crypto.KEY_SECRET_SIZE];
        crypto.ecdh.init(kp.getPrivate());
        crypto.ecdh.generateSecret(pub, (short) 0, (short) Crypto.KEY_PUB_SIZE, secret, (short) 0);
        return secret;
    }

    private static AESKey buildAESKey(Crypto crypto, KeyPair kp, byte[] pubBytes) {
        byte[] secret = ecdhSharedSecret(crypto, kp, pubBytes);
        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        key.setKey(secret, (short) 0);
        return key;
    }

    private byte[] decryptPhonon(Crypto crypto, KeyPair kp, byte[] decryptPub, byte[] encPhonon) {
        byte[] decPhonon = new byte[Phonon.ENC_PHONON_LEN];
        Cipher aesEcbCipher;
        AESKey key = buildAESKey(crypto, kp, decryptPub);
        aesEcbCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        aesEcbCipher.init(key, Cipher.MODE_DECRYPT);
        aesEcbCipher.doFinal(encPhonon, (short) 0, (short) Phonon.ENC_PHONON_LEN, decPhonon, (short) 0);
        return decPhonon;
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

    public boolean phononIsEmpty(short i) {
        return phonons[i] == null;
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
        Phonon p = unpackPhonon(priv, payload);
        phonons[i] = p;
        this.depositNonce = nonce;
        return i;
    }

    //==========================================================================================================
    // SALTS
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

    // Get the salt at index `i`
    // @returns 4 byte salt
    public byte[] getSalt(short i) {
        byte[] s = new byte[4];
        Util.arrayCopyNonAtomic(this.salts, (byte) (i * INT_LEN), s, (byte) 0, INT_LEN);
        return s;
    }

    // Remove salt at index `i`. 
    // WARNING: This should only be called if the salt has NOT been handed out. Removing 
    // a salt means you will not be able to decrypt a phonon using it, obviously.
    public void removeSalt(short i) {
        byte[] empty = { 0, 0, 0, 0 };
        Util.arrayCopy(empty, (short) 0, this.salts, (short) (i * INT_LEN), INT_LEN);
        Util.arrayCopy(empty, (short) 0, this.saltsTs, (short) (i * INT_LEN), INT_LEN);
        return;
    }

    //==========================================================================================================
    // TRANSFER
    //==========================================================================================================
    // Ensure we can transfer out a phonon at the given index.
    // @returns true if there is a phonon available at that index
    public boolean canTransfer(short i) {
        return phonons[i] != null;
    }

    // Transfer phonon at index i out. This requires a public key derived from the recipient's salt
    // as well as a random key pair (`kp`) generated before calling this function. `kp` is generated
    // during this APDU transaction and is discarded immediately. It is returned along with the
    // encrypted phonon.
    //  @returns length of encrypted payload and copies that payload to `output`
    public short transfer(short i, byte[] receivingPub, KeyPair kp, Crypto crypto, byte[] output) {
        // Sanity check - this should never get hit because canTransfer should be called first
        if (phonons[i] == null) {
            return 0;
        }
        // Export the phonon and delete it on card
        byte[] p = phonons[i].export();
        
        // Encrypt the payoad
        Cipher aesEcbCipher;
        AESKey key = buildAESKey(crypto, kp, receivingPub);
        aesEcbCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        aesEcbCipher.init(key, Cipher.MODE_ENCRYPT);
        short encLen = aesEcbCipher.doFinal(p, (short) 0, (short) Phonon.ENC_PHONON_LEN, output, (short) 0);
        return encLen;
    }

    // Delete phonon at index i
    public void delete(short i) {
        phonons[i] = null;
    }

    //==========================================================================================================
    // RECEIVE
    //==========================================================================================================
    
    // Ensure that a phonon may be received given the salt-based key pair. This function ensures
    // that there is an available phonon slot and that the decrypted phonon checksum matches the
    // payload.
    // @returns true if the phonon can be properly decrypted and stored
    public boolean canReceive(byte[] decryptPub, KeyPair kp, Crypto crypto, byte[] encPhonon) {
        if (getNextPhononSlot() == NO_PHONON_SLOT) {
            return false;
        }
        // Validate checksum (ENC_PHONON_PADDING bytes)
        byte[] decPhonon = decryptPhonon(crypto, kp, decryptPub, encPhonon);
        // Checksum the decrypted phonon data
        byte[] checksum = new byte[Crypto.KEY_SECRET_SIZE];
        crypto.sha256.doFinal(decPhonon, (short) 0, (short) Phonon.EXPORTED_PHONON_LEN, checksum, (short) 0);
        // Compare the included checksum
        byte[] cs = new byte[Phonon.ENC_PHONON_PADDING];
        Util.arrayCopyNonAtomic(decPhonon, (short) Phonon.EXPORTED_PHONON_LEN, cs, (short) 0, Phonon.ENC_PHONON_PADDING);
        byte match = Util.arrayCompare(checksum, (short) 0, cs, (short) 0, (short) Phonon.ENC_PHONON_PADDING);
        return match == (byte) 0;
    }

    // Receive a phonon in encrypted form. A public key must be provided, which is combined with
    // the private key at the desired salt slot (already instantiated at `kp`) to derived the
    // encryption secret via ECDH. Once the phonon is decrypted, it is unpacked and saved
    // to storage at the next available phonon slot
    // @returns phonon slot index
    public short receive(byte[] decryptPub, KeyPair kp, Crypto crypto, byte[] encPhonon) {
        // Decrypt payload
        byte[] decPhonon = decryptPhonon(crypto, kp, decryptPub, encPhonon);
        // Unpack decrypted phonon
        // 1. Get static phonon data (without privkey)
        byte[] staticPhononData = new byte[Phonon.DEPOSIT_DATA_LEN];
        Util.arrayCopy(decPhonon, (short) 0, staticPhononData, (short) 0, (short) Phonon.DEPOSIT_DATA_LEN);
        // 2. Get phonon private key
        byte[] phononPriv = new byte[Crypto.KEY_SECRET_SIZE];
        Util.arrayCopy(decPhonon, (short) (Phonon.DEPOSIT_DATA_LEN), phononPriv, (short) 0, (short) Crypto.KEY_SECRET_SIZE);
        // 3. Create Phonon object
        Phonon ph = unpackPhonon(phononPriv, staticPhononData);
        short phononSlot = getNextPhononSlot();
        phonons[phononSlot] = ph;
        return phononSlot;
    }

    //==========================================================================================================
    // WITHDRAWALS
    //==========================================================================================================
    
    // Withdraw a phonon by signing `data` with its private key and removing it
    // from storage. This produces a signature template containing:
    // [TLV_SIGNATURE_TEMPLATE][TLV_PUB_KEY][pubKeyLen][pubKey][0x30][sigLen][sig]
    // Where sig futher breaks down into
    // [2][rLen][R][2][sLen][S]
    // This provides all the data necessary for signature verification
    // @returns signature template outlined above
    public byte[] withdraw(short i, byte[] data) {
        // Sign the data 
        byte[] sig = new byte[75];
        short sigLen = phonons[i].sign(data, sig);
        // Get the public key. We will return it with the sig
        byte[] pub = phonons[i].getPubKey();
        // Create signature template
        byte[] out = new byte[(short) (Crypto.KEY_PUB_SIZE + sigLen + 3)];
        short off = 0;
        out[off] = KeycardApplet.TLV_SIGNATURE_TEMPLATE; off++;
        // PubKey
        out[off] = KeycardApplet.TLV_PUB_KEY; off++;
        out[off] = Crypto.KEY_PUB_SIZE; off++;
        Util.arrayCopy(pub, (short) 0, out, off, Crypto.KEY_PUB_SIZE);
        off += (short) Crypto.KEY_PUB_SIZE;
        // Signature
        Util.arrayCopy(sig, (short) 0, out, off, sigLen);
        off += sigLen;
        // Remove the phonon and return withdrawal signature
        delete(i);
        return out;
    }
}
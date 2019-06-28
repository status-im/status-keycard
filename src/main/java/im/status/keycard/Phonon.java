package im.status.keycard;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;

public class Phonon {
    static final public byte EXTRA_DATA_LEN = 33;
    static final public byte DEPOSIT_DATA_LEN = 38;
    static final public byte SERIALIZED_PHONON_LEN = (short) (DEPOSIT_DATA_LEN + Crypto.KEY_PUB_SIZE);
    static final public byte SERIALIZED_DEPOSIT_LEN = (short) (DEPOSIT_DATA_LEN + Crypto.KEY_SECRET_SIZE);
    static final public byte EXPORTED_PHONON_LEN = (short) (DEPOSIT_DATA_LEN + Crypto.KEY_SECRET_SIZE);
    // We need to pad this buffer to the AES block size (16 bytes)
    static final public byte ENC_PHONON_PADDING = (short) (16 - EXPORTED_PHONON_LEN % 16);
    static final public byte ENC_PHONON_LEN = (short) (ENC_PHONON_PADDING + EXPORTED_PHONON_LEN);

    private byte networkId;
    private byte assetId;
    private ECPrivateKey owner;
    private short amount;
    private byte decimals;
    private byte[] extraData;

    Phonon(byte _networkId, byte _assetId, byte[] _owner, short _amount, byte _decimals, byte[] _extraData) {
        if (_owner.length != 32 || _extraData.length != 33) {
            return;
        }
        // Copy data
        this.networkId = _networkId;
        this.assetId = _assetId;
        this.amount = _amount;
        this.decimals = _decimals;
        this.extraData = new byte[EXTRA_DATA_LEN];
        Util.arrayCopy(_extraData, (short) 0, this.extraData, (short) 0, (short) _extraData.length);
        // Save the private key
        Crypto crypto = new Crypto();
        SECP256k1 secp256k1 = new SECP256k1(crypto);
        this.owner = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
        secp256k1.setCurveParameters(this.owner);
        this.owner.setS(_owner, (short) 0, Crypto.KEY_SECRET_SIZE);
    }

    public byte[] getPubKey() {
        byte[] pub = new byte[Crypto.KEY_PUB_SIZE];
        Crypto crypto = new Crypto();
        SECP256k1 secp256k1 = new SECP256k1(crypto);
        secp256k1.derivePublicKey(this.owner, pub, (short) 0);
        return pub;
    }

    // Serialize static phonon data (NOT including private key)
    public byte[] serialize() {
        byte[] d = JCSystem.makeTransientByteArray(SERIALIZED_PHONON_LEN, JCSystem.CLEAR_ON_RESET);
        short off = 0;
        d[off] = this.networkId; off++;
        d[off] = this.assetId; off++;
        byte[] a = PhononNetwork.shortToBytes(this.amount);
        d[off] = a[0]; off++;
        d[off] = a[1]; off++;
        d[off] = this.decimals; off++;
        Util.arrayCopy(this.extraData, (short) 0, d, (short) off, (short) this.extraData.length);
        off += this.extraData.length;
        byte[] pubBuf = getPubKey();
        Util.arrayCopy(pubBuf, (short) 0, d, (short) off, (short) Crypto.KEY_PUB_SIZE);
        return d;
    }

    // Export the phonon (with private key)
    public byte[] export() {
        byte[] d = JCSystem.makeTransientByteArray((short) (ENC_PHONON_LEN), JCSystem.CLEAR_ON_RESET);
        // We will left pad with zeros
        short off = 0; //(short) (ENC_PHONON_PADDING - 1);
        d[off] = this.networkId; off++;
        d[off] = this.assetId; off++;
        byte[] a = PhononNetwork.shortToBytes(this.amount);
        d[off] = a[0]; off++;
        d[off] = a[1]; off++;
        d[off] = this.decimals; off++;
        Util.arrayCopy(this.extraData, (short) 0, d, (short) off, (short) this.extraData.length);
        off += this.extraData.length;
        this.owner.getS(d, off); off += (short) Crypto.KEY_SECRET_SIZE;
        // Sha256 checksum (we will only use ENC_PHONON_PADDING bytes)
        byte[] checksum = new byte[Crypto.KEY_SECRET_SIZE];
        Crypto crypto = new Crypto();
        crypto.sha256.doFinal(d, (short) 0, off, checksum, (short) 0);
        Util.arrayCopyNonAtomic(checksum, (short) 0, d, off, (short) ENC_PHONON_PADDING);
        return d;
    }

    // Sign a message with this.owner (phonon key)
    public short sign(byte[] data, byte[] output) {
        // Create the message digest
        byte[] msg = new byte[Crypto.KEY_SECRET_SIZE];
        Crypto crypto = new Crypto();
        crypto.sha256.doFinal(data, (short) 0, (short) data.length, msg, (short) 0);
        // Sign
        Signature tmpSig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        tmpSig.init(this.owner, Signature.MODE_SIGN);
        short sigLen = tmpSig.signPreComputedHash(msg, (short) 0, MessageDigest.LENGTH_SHA_256, output, (short) 0);
        sigLen += crypto.fixS(output, (short) 0);
        return sigLen;
    }

}
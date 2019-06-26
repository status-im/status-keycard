package im.status.keycard;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;

public class Phonon {
    static final public byte EXTRA_DATA_LEN = 33;
    static final public byte DEPOSIT_DATA_LEN = 38;
    static final public byte SERIALIZED_PHONON_LEN = (short) (DEPOSIT_DATA_LEN + Crypto.KEY_PUB_SIZE);
    static final public byte SERIALIZED_DEPOSIT_LEN = (short) (DEPOSIT_DATA_LEN + Crypto.KEY_SECRET_SIZE);

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
        Crypto crypto = new Crypto();
        SECP256k1 secp256k1 = new SECP256k1(crypto);
        short pubLen = secp256k1.derivePublicKey(this.owner, d, off);
        off += pubLen;
        return d;
    }
/*
    // Export the phonon (with private key)
    public byte[] export() {
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
        this.owner.getS(d, off);
        return d;
    }
*/
}
package im.status.keycard;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class Phonon {
    public byte networkId;
    public byte assetId;
    public byte[] owner;
    public short amount;
    public byte decimals;
    public byte[] extraData;

    Phonon(byte _networkId, byte _assetId, byte[] _owner, short _amount, byte _decimals, byte[] _extraData) {
        if (_owner.length != 32 || _extraData.length != 33) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        this.networkId = _networkId;
        this.assetId = _assetId;
        this.amount = _amount;
        this.decimals = _decimals;
        Util.arrayCopy(this.owner, (short) 0, _owner, (short) 0, (short) _owner.length);
        Util.arrayCopy(this.extraData, (short) 0, _extraData, (short) 0, (short) _extraData.length);

    }
}
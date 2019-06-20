package im.status.keycard;
import javacard.framework.*;

public class PhononNetwork {
    private short depositNonce;
    private short[] salts;
    private short[] saltsTs;
    private Phonon[] phonons;

    PhononNetwork() {
        this.depositNonce = 0;
        this.phonons = new Phonon[5];
        this.salts = new short[5];
        this.saltsTs = new short[5];
    }
}
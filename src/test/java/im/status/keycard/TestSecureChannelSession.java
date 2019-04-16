package io.gridplus.safecard;

import io.gridplus.safecard.applet.SecureChannelSession;

public class TestSecureChannelSession extends SecureChannelSession {
  public void setOpen() {
    super.setOpen();
  }

  public byte getPairingIndex() {
    return getPairing().getPairingIndex();
  }
}

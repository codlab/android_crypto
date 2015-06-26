package eu.codlab.crypto.events;

import java.security.KeyPair;

/**
 * Created by kevinleperf on 26/06/15.
 */
public class EventKeysGenerated {
    private KeyPair _key_pair;

    public EventKeysGenerated(KeyPair key_pair) {
        _key_pair = key_pair;
    }

    public KeyPair getKeyPair() {
        return _key_pair;
    }
}

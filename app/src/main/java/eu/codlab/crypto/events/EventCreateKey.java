package eu.codlab.crypto.events;

/**
 * Created by kevinleperf on 26/06/15.
 */
public class EventCreateKey {
    private int _key_size;

    public EventCreateKey(int key_size) {
        _key_size = key_size;
    }

    public int getKeySize() {
        return _key_size;
    }
}

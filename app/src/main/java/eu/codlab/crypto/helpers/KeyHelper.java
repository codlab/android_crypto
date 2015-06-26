package eu.codlab.crypto.helpers;

import java.security.KeyPair;

import de.greenrobot.event.EventBus;
import eu.codlab.crypto.events.EventCreateKey;
import eu.codlab.crypto.events.EventKeysGenerated;
import eu.codlab.crypto.core.keys.KeyUtil;

/**
 * Created by kevinleperf on 26/06/15.
 */
public class KeyHelper {
    private static KeyHelper _instance = new KeyHelper();

    public static void generateKeysAsyncUsingEventBus(int key_size) {
        EventBus.getDefault().post(new EventCreateKey(key_size));
    }

    public static KeyPair generateKeysSync(int key_size) {
        return KeyUtil.generateKey(key_size);
    }


    private KeyHelper() {
        EventBus.getDefault().register(this);
    }

    public void onEventAsync(EventCreateKey create_key) {
        KeyPair pair = KeyUtil.generateKey(create_key.getKeySize());

        EventBus.getDefault().post(new EventKeysGenerated(pair));
    }
}

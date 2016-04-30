package eu.codlab.crypto.core.keys;

import java.security.PrivateKey;
import java.security.PublicKey;

import eu.codlab.crypto.core.stream.CypherRSA;

/**
 * Created by kevinleperf on 24/02/15.
 */
public class PublicPrivateKeyManager {
    private CypherRSA _rsa;
    private int _key_size;
    private PublicKey _public_key;
    private PrivateKey _private_key;

    private PublicPrivateKeyManager() {

    }

    private PublicPrivateKeyManager(int key_size) {
        _key_size = key_size;
        _rsa = new CypherRSA(_key_size);
    }

    public static PublicPrivateKeyManager createKeyManager(int key_size) {
        return new PublicPrivateKeyManager(key_size);
    }

    private void generateKeys() {
        KeyUtil.generateKey(_key_size);
    }

    public boolean setkeysFromStorage(PublicKey public_key, PrivateKey private_key) {
        try {
            _public_key = public_key;
            _private_key = private_key;
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean setKeysFromStorage(byte[] public_key, byte[] private_key) {
        try {
            _public_key = KeyUtil.importPublicKey(public_key);
            _private_key = KeyUtil.importPrivateKey(private_key);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public byte[] exportPublicKey() {
        return KeyUtil.exportPublicKey(_public_key);
    }

    public byte[] exportPrivateKey() {
        return KeyUtil.exportPrivateKey(_private_key);
    }

    public PublicKey getPublicKey() {
        return _public_key;
    }

    public byte[] encrypt(String text) {
        return encrypt(text.getBytes());
    }

    public byte[] encrypt(byte[] bytes) {
        return _rsa.encrypt(bytes, _private_key);
    }

    public byte[] decrypt(String text) {
        return decrypt(text.getBytes());
    }

    public byte[] decrypt(byte[] bytes) {
        return _rsa.decrypt(bytes, _public_key);
    }


}

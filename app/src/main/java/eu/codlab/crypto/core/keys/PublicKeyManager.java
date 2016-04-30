package eu.codlab.crypto.core.keys;

import java.security.PublicKey;

import eu.codlab.crypto.core.stream.CypherRSA;

/**
 * Perform operations on values using a given public key
 * <p/>
 * Created by kevinleperf on 24/02/15.
 */
public class PublicKeyManager {
    private int _key_size;
    private PublicKey _public_key;
    private CypherRSA _rsa;

    private PublicKeyManager() {
    }

    private PublicKeyManager(byte[] public_key, int key_size) {
        this();
        setKeysFromStorage(public_key);
        _key_size = key_size;

        _rsa = new CypherRSA(_key_size);
    }

    private PublicKeyManager(PublicKey key, int key_size) {
        _public_key = key;
        _key_size = key_size;

        _rsa = new CypherRSA(_key_size);
    }

    /**
     * Create an instance speciyfing the given public key
     *
     * @param public_key
     * @return
     */
    public static PublicKeyManager createKeyManager(PublicKey public_key,
                                                    int key_size) {
        return new PublicKeyManager(public_key, key_size);
    }

    /**
     * Create an instance specifying the given public key byte array representing the internal
     * representation
     *
     * @param public_key
     * @return
     */
    public static PublicKeyManager createKeyManager(byte[] public_key,
                                                    int _key_size) {
        return new PublicKeyManager(public_key, _key_size);
    }

    private boolean setKeysFromStorage(byte[] public_key) {
        try {
            _public_key = KeyUtil.importPublicKey(public_key);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public byte[] exportPublicKey() {
        return KeyUtil.exportPublicKey(_public_key);
    }

    public PublicKey getPublicKey() {
        return _public_key;
    }

    /**
     * Encrypt the text using the public key
     * <p/>
     * Example : using somebody's public ey, you encrypt a text he will then be able to decrypt
     *
     * @param text
     * @return
     */
    public byte[] encrypt(String text) {
        return encrypt(text.getBytes());
    }

    /**
     * ENcrypt the given byte array using the public key
     * <p/>
     * Example : using somebody's public ey, you encrypt a text he will then be able to decrypt
     *
     * @param bytes
     * @return
     */
    public byte[] encrypt(byte[] bytes) {
        return _rsa.encrypt(bytes, _public_key);
    }

    /**
     * Decrypt the given byte array using the public key
     * <p/>
     * Example : someone sent you a text AND a signature (encryption of the message hash)
     * you can check it is the owner by decrypting the signature and then compare the decrypting hash
     * with the hash inside the signature
     *
     * @param bytes
     * @return
     */
    public byte[] decrypt(byte[] bytes) {
        return _rsa.decrypt(bytes, _public_key);
    }


}

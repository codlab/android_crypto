package eu.codlab.crypto.core.keys;

import java.security.PublicKey;

import eu.codlab.crypto.core.stream.CypherRSA;
import eu.codlab.crypto.core.keys.logic.KeyUtil;

/**
 * Perform operations on values using a given public key
 *
 * Created by kevinleperf on 24/02/15.
 */
public class PublicKeyManager {
    private int _key_size;
    private PublicKey _public_key;

    private PublicKeyManager() {
    }

    private PublicKeyManager(byte[] public_key) {
        this();
        setKeysFromStorage(public_key);
    }

    private PublicKeyManager(PublicKey key){
        _public_key = key;
    }

    /**
     * Create an instance speciyfing the given public key
     *
     * @param public_key
     * @return
     */
    public static PublicKeyManager createKeyManager(PublicKey public_key){
        return new PublicKeyManager(public_key);
    }

    /**
     * Create an instance specifying the given public key byte array representing the internal
     * representation
     *
     * @param public_key
     * @return
     */
    public static PublicKeyManager createKeyManager(byte[] public_key) {
        return new PublicKeyManager(public_key);
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
     *
     * Example : using somebody's public ey, you encrypt a text he will then be able to decrypt
     * @param text
     * @return
     */
    public byte[] encrypt(String text) {
        return encrypt(text.getBytes());
    }

    /**
     * ENcrypt the given byte array using the public key
     *
     * Example : using somebody's public ey, you encrypt a text he will then be able to decrypt
     * @param bytes
     * @return
     */
    public byte[] encrypt(byte[] bytes) {
        return CypherRSA.encrypt(bytes, _public_key);
    }

    /**
     * Decrypt the given byte array using the public key
     *
     * Example : someone sent you a text AND a signature (encryption of the message hash)
     * you can check it is the owner by decrypting the signature and then compare the decrypting hash
     * with the hash inside the signature
     *
     * @param bytes
     * @return
     */
    public byte[] decrypt(byte[] bytes) {
        return CypherRSA.decrypt(bytes, _public_key);
    }


}

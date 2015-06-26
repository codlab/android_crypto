package eu.codlab.crypto.keys.logic;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import eu.codlab.crypto.utils.Base64Coder;
import eu.codlab.crypto.utils.Constants;

/**
 *
 * This class provides information to :
 *
 * - generate a public / private key pair depending on the size in parameters
 *
 * - export a given private key to a byte array
 * - export a given public key to a byte array
 *
 * - create a public key from a byte array
 * - create a private key from a byte array
 *
 * The export is done using x509
 * The import is done using PKCS8
 *
 * Created by kevinleperf on 24/02/15.
 */
public class KeyUtil {
    /**
     * Generate a key pair using the given key size
     *
     * WARNING consider using size such as 2048 / 4096
     *
     * @param key_size
     * @return
     */
    public static KeyPair generateKey(int key_size) {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Constants.ALGORITHM);
            keyGen.initialize(key_size);
            final KeyPair key = keyGen.generateKeyPair();

            return key;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;

    }

    public static byte[] exportPublicKey(PublicKey key) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key.getEncoded());
        return x509EncodedKeySpec.getEncoded();
    }

    public static byte[] exportPrivateKey(PrivateKey key) {
        PKCS8EncodedKeySpec x509EncodedKeySpec = new PKCS8EncodedKeySpec(key.getEncoded());
        return x509EncodedKeySpec.getEncoded();
    }

    public static PublicKey importPublicKey(byte[] encoded)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded);
        PublicKey publicKey = getKeyFactory().generatePublic(publicKeySpec);
        return publicKey;
    }

    public static PrivateKey importPrivateKey(byte[] encoded)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey privateKey = getKeyFactory().generatePrivate(keySpec);
        return privateKey;
    }

    private static KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(Constants.ALGORITHM);
    }
}

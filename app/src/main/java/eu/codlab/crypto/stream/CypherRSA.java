package eu.codlab.crypto.stream;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import eu.codlab.crypto.utils.Constants;

/**
 *
 * Simple class to help encrypt / decrypt stream or string from RSA
 * Created by kevinleperf on 28/06/13.
 */
public class CypherRSA {

    /**
     * Encrypt the given text using the private key
     * This call is intended to be used as a signature
     * during exchanges
     *
     * @param bytes
     * @param key
     * @return
     */
    public static byte[] encrypt(byte[] bytes, PrivateKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(Constants.ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return blockCipher(cipher, bytes, Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Encrypt the given text using the private key
     * This call is intended to be used as a signature
     * during exchanges
     *
     * @param text
     * @param key
     * @return
     */
    public static byte[] encrypt(String text, PrivateKey key) {
        if (key != null && text != null) {
            return encrypt(text.getBytes(), key);
        }
        return null;
    }

    /**
     * Encrypt the given text using the provided public key
     * This call is intended to be used as a cypher stream for a client
     *
     * @param bytes
     * @param key
     * @return
     */
    public static byte[] encrypt(byte[] bytes, PublicKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(Constants.ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return blockCipher(cipher, bytes, Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Encrypt the given text using the provided public key
     * This call is intended to be used as a cypher stream for a client
     *
     * @param text
     * @param key
     * @return
     */
    public static byte[] encrypt(String text, PublicKey key) {
        if (key != null && text != null) {
            return encrypt(text.getBytes(), key);
        }
        return null;
    }

    /**
     * Decrypt the specified text/stream using the public key
     * This is to verify the signature of a distant client
     * <p/>
     * I.e. : someone sent a text with a signature, the signature is created using the private key,
     * so the receiver needs to use the remote client public key to unencrypt it
     * while the text is simply decyphered using the current client private key
     *
     * @param text
     * @param key
     * @return
     */
    public static byte[] decrypt(byte[] text, PublicKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(Constants.ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return blockCipher(cipher, text, Cipher.DECRYPT_MODE);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt the specified text/stream using the specified private key
     * This is to have access to the content
     *
     * @param text
     * @param key
     * @return
     */
    public static byte[] decrypt(byte[] text, PrivateKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(Constants.ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return blockCipher(cipher, text, Cipher.DECRYPT_MODE);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt the specified text/stream using the public key
     * This is to verify the signature of a distant client
     * <p/>
     * I.e. : someone sent a text with a signature, the signature is created using the private key,
     * so the receiver needs to use the remote client public key to unencrypt it
     * while the text is simply decyphered using the current client private key
     * <p/>
     * Returns the result as a String
     *
     * @param text
     * @param key
     * @return
     */
    public static String decryptToString(byte[] text, PublicKey key) {
        if (key != null && key != null) {
            return new String(decrypt(text, key));
        }
        return null;
    }

    /**
     * Decrypt the specified text/stream using the specified private key
     * Return the result as a String
     *
     * @param text
     * @param key
     * @return
     */
    public static String decryptToString(byte[] text, PrivateKey key) {
        if (key != null && key != null) {
            return new String(decrypt(text, key));
        }
        return null;
    }

    private static byte[] blockCipher(Cipher cipher, byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException {
        // string initialize 2 buffers.
        // scrambled will hold intermediate results
        byte[] scrambled = new byte[0];

        // toReturn will hold the total result
        byte[] toReturn = new byte[0];
        // if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        int length = (mode == Cipher.ENCRYPT_MODE) ? 200 : 256;

        // another buffer. this one will hold the bytes that have to be modified in this step
        byte[] buffer = new byte[length];

        for (int i = 0; i < bytes.length; i++) {

            // if we filled our buffer array we have our block ready for de- or encryption
            if ((i > 0) && (i % length == 0)) {
                //execute the operation
                scrambled = cipher.doFinal(buffer);
                // add the result to our total result.
                toReturn = append(toReturn, scrambled);
                // here we calculate the length of the next buffer required
                int newlength = length;

                // if newlength would be longer than remaining bytes in the bytes array we shorten it.
                if (i + length > bytes.length) {
                    newlength = bytes.length - i;
                }
                // clean the buffer array
                buffer = new byte[newlength];
            }
            // copy byte into our buffer.
            buffer[i % length] = bytes[i];
        }

        // this step is needed if we had a trailing buffer. should only happen when encrypting.
        // example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
        scrambled = cipher.doFinal(buffer);

        // final step before we can return the modified data.
        toReturn = append(toReturn, scrambled);

        return toReturn;
    }

    private static byte[] append(byte[] prefix, byte[] suffix) {
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i = 0; i < prefix.length; i++) {
            toReturn[i] = prefix[i];
        }
        for (int i = 0; i < suffix.length; i++) {
            toReturn[i + prefix.length] = suffix[i];
        }
        return toReturn;
    }
}

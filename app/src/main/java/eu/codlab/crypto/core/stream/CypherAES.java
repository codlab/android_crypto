package eu.codlab.crypto.core.stream;

import android.annotation.SuppressLint;

import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import eu.codlab.crypto.core.utils.Base64Coder;
import eu.codlab.crypto.core.utils.Constants;

public class CypherAES {


    private static final int ITERATION_COUNT = 65536 >> 1;
    private static final int KEY_LENGTH = 256;
    private Cipher ecipher;
    private Cipher dcipher;

    @SuppressLint("TrulyRandom")
    CypherAES(String passPhrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(Constants.KEY_FACTORY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(passPhrase.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), Constants.AES);

        ecipher = Cipher.getInstance(Constants.CYPHER_ENCODE);
        ecipher.init(Cipher.ENCRYPT_MODE, secret);

        dcipher = Cipher.getInstance(Constants.CYPHER_DECODE);
        byte[] iv = ecipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        dcipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
    }

    /**
     * Encrypt a given string returning
     *
     * @param encrypt
     * @return
     * @throws Exception
     */
    public String encryptToBase64(String encrypt) throws Exception {
        byte[] bytes = encrypt.getBytes(Constants.UTF8);
        byte[] encrypted = encrypt(bytes);
        return new String(Base64Coder.encode(encrypted));
    }

    /**
     * Encrypt a byte array to a byte array using the given information
     *
     * @param plain
     * @return
     * @throws Exception
     */
    public byte[] encrypt(byte[] plain) throws Exception {
        return ecipher.doFinal(plain);
    }

    /**
     * Decrypt the given encrypted text using the original information
     *
     * @param encrypt
     * @return
     * @throws Exception
     */
    public String decryptToUTF8(String encrypt) throws Exception {
        byte[] bytes = Base64Coder.decode(encrypt);
        byte[] decrypted = decrypt(bytes);
        return new String(decrypted, Constants.UTF8);
    }

    /**
     * Decrypted the given byte array using the given decoding information
     *
     * @param encrypted
     * @return
     * @throws Exception
     */
    public byte[] decrypt(byte[] encrypted) throws Exception {
        return dcipher.doFinal(encrypted);
    }

}

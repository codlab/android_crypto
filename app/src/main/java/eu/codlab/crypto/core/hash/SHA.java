package eu.codlab.crypto.core.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by kevinleperf on 27/03/2014.
 */
public class SHA {
    public static String encode(String string) {
        byte[] uniqueKey = string.getBytes();
        byte[] hash = null;

        try {
            hash = MessageDigest.getInstance("SHA-256").digest(uniqueKey);
        } catch (NoSuchAlgorithmException e) {
            throw new Error("No SHA support in this VM.");
        }

        StringBuilder hashString = new StringBuilder();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(hash[i]);
            if (hex.length() == 1) {
                hashString.append('0');
                hashString.append(hex.charAt(hex.length() - 1));
            } else
                hashString.append(hex.substring(hex.length() - 2));
        }
        return hashString.toString();
    }

}
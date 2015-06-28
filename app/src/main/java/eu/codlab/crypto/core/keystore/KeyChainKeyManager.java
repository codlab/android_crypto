package eu.codlab.crypto.core.keystore;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyChain;
import android.util.Log;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.X509KeyManager;

import eu.codlab.crypto.BuildConfig;

/**
 * Create a simple KeyChainKeyManager which will help provide the right certificate during
 * negociations
 */
@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
public class KeyChainKeyManager implements X509KeyManager {
    private static void log(String tag, String text) {
        if (BuildConfig.DEBUG) {
            Log.d(tag, text);
        }
    }

    private final static String TAG = "KeyChainKeyManager";
    private String mClientAlias;
    private final X509Certificate[] mCertificateChain;
    private final PrivateKey mPrivateKey;

    public static KeyChainKeyManager fromAlias(Context context, String alias)
            throws CertificateException {
        X509Certificate[] certificateChain = null;
        try {
            certificateChain = KeyChain.getCertificateChain(context, alias);
        } catch (Exception e) {
            log(TAG, alias + "certificate chain" + e);
            e.printStackTrace();
        }

        PrivateKey privateKey = null;
        try {
            privateKey = KeyChain.getPrivateKey(context, alias);
        } catch (Exception e) {
            log(TAG, alias + "private key chain" + e);
            e.printStackTrace();
        }

        if (certificateChain == null || privateKey == null) {
            throw new CertificateException("Can't access certificate from keystore");
        }

        return new KeyChainKeyManager(alias, certificateChain, privateKey);
    }

    private KeyChainKeyManager(
            String clientAlias, X509Certificate[] certificateChain,
            PrivateKey privateKey) {

        log(TAG, "constructKeyChainKeyManager " + clientAlias + " " + privateKey.toString());
        mClientAlias = clientAlias;
        mCertificateChain = certificateChain;
        mPrivateKey = privateKey;
    }


    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        log(TAG, "chooseClientAlias " + Arrays.toString(keyTypes) + " " + Arrays.toString(issuers)
                + " " + socket + " " + mClientAlias);
        return mClientAlias;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return mClientAlias;
    }

    public X509Certificate[] getCertificateChain(String alias) {
        log(TAG, "getCertificateChain " + alias + " " + mCertificateChain);
        return mCertificateChain;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[]{mClientAlias};
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[]{mClientAlias};
    }

    public PrivateKey getPrivateKey(String alias) {
        return mPrivateKey;
    }
}
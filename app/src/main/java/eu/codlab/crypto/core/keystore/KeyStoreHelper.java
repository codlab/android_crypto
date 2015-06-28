package eu.codlab.crypto.core.keystore;

import android.annotation.TargetApi;
import android.app.Activity;
import android.os.Build;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import eu.codlab.crypto.BuildConfig;
import eu.codlab.crypto.core.utils.Constants;

@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
/**
 * Provide ability to retrieve a specific Certificate from the internal device
 *
 * e.g. : certificate based serverside authentication
 */
public class KeyStoreHelper {
    private TrustManagerFactory _trust_manager_factory;
    private KeyStore _key_store;
    private Activity _activity;
    private IKeyStoreListener _key_store_listener;

    private KeyStoreHelper() {

    }

    public KeyStoreHelper(Activity activity, IKeyStoreListener key_store_listener)
            throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        this();
        _activity = activity;
        _key_store_listener = key_store_listener;
        try {
            KeyManagerFactory _key_manager_factory = KeyManagerFactory.getInstance(Constants.X509);
            _key_store = KeyStore.getInstance(Constants.AndroidCAStore);
            _key_store.load(null);
            String default_algorithm = KeyManagerFactory.getDefaultAlgorithm();
            _trust_manager_factory = TrustManagerFactory.getInstance(default_algorithm);
            _key_manager_factory.init(_key_store, null);
            _trust_manager_factory.init(_key_store);
        } catch (UnrecoverableKeyException e) {
            if (BuildConfig.DEBUG) {
                e.printStackTrace();
            }
        }

    }

    public Enumeration<String> getAliases() {
        Enumeration<String> aliases = null;
        try {
            aliases = _key_store.aliases();
        } catch (KeyStoreException e) {
            if (BuildConfig.DEBUG) {
                e.printStackTrace();
            }
        }
        return aliases;
    }

    public X509Certificate getX509CertificateFor(String alias) {
        try {
            return (X509Certificate) _key_store.getCertificate(alias);
        } catch (KeyStoreException e) {
            if (BuildConfig.DEBUG) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public void loadCertificateFor(String cdn, String host, int port) {
        try {
            String alias = null;
            Enumeration<String> aliases = getAliases();

            if (aliases != null) {
                while (aliases.hasMoreElements() && alias == null) {
                    alias = aliases.nextElement();
                    X509Certificate cert = getX509CertificateFor(alias);
                    if (!cert.getSubjectDN().getName().equals(cdn)) {
                        alias = null;
                    }
                }
            }
            loadCertificateFor(alias, cdn, host, port);
        } catch (Exception e) {
            _key_store_listener.onException(e);
        }
    }

    public void loadCertificateFor(String alias, String cdn, final String host, int port) {
        try {
            onLoadedAlias(alias);
        } catch (Exception e) {
            KeyChain.choosePrivateKeyAlias(_activity, new KeyChainAliasCallback() {
                @Override
                public void alias(String alias) {
                    onLoadedAlias(alias);
                }
            }, new String[]{Constants.RSA, Constants.DSA}, null, host, port, alias);
        }
    }

    private void onLoadedAlias(String alias) {
        try {

            SSLContext ssl_context = SSLContext.getInstance(Constants.TLS);


            KeyManager[] manager = new KeyManager[]{KeyChainKeyManager.fromAlias(_activity, alias)};
            TrustManager[] trust = _trust_manager_factory.getTrustManagers();
            TrustManager[] trust_manager = getDefaultTrustManagerArray(trust);

            ssl_context.init(manager,
                    trust_manager,
                    new SecureRandom());

            _key_store_listener.onKeyStoreInformationLoaded(ssl_context,
                    manager,
                    trust_manager);
        } catch (CertificateException | NoSuchAlgorithmException | KeyManagementException e) {
            _key_store_listener.onException(e);
        }

    }

    /**
     * Create a simple Default Trust Manager Array from given information
     * <p/>
     * TODO throw issues on errors !
     *
     * @param trust_managers The original trust managers we wrapped in the library
     * @return the wrapped trust_managers
     */
    private static TrustManager[] getDefaultTrustManagerArray(final TrustManager[] trust_managers) {
        return new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        X509Certificate[] certs = null;
                        for (TrustManager original : trust_managers) {
                            try {
                                certs = ((X509TrustManager) original).getAcceptedIssuers();
                            } catch (Exception e) {
                                if (BuildConfig.DEBUG) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        return certs;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String auth_type) {
                        for (TrustManager original : trust_managers) {
                            try {
                                ((X509TrustManager) original).checkClientTrusted(certs, auth_type);
                            } catch (Exception e) {
                                if (BuildConfig.DEBUG) {
                                    e.printStackTrace();
                                }
                            }
                        }
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String auth_type) {
                        for (TrustManager original : trust_managers) {
                            try {
                                ((X509TrustManager) original).checkServerTrusted(certs, auth_type);
                            } catch (Exception e) {
                                if (BuildConfig.DEBUG) {
                                    e.printStackTrace();
                                }
                            }
                        }
                    }
                }
        };
    }

}

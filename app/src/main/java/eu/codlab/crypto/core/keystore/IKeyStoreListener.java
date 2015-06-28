package eu.codlab.crypto.core.keystore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * Interface to listen for KeyStoreHelper events
 * SSLContext can be used as specific SSL information during negociations in libraries
 * likes Ion, Retrofit, etc...
 *
 * e.g. : serverside certificate authentication
 */
public interface IKeyStoreListener {
    void onKeyStoreInformationLoaded(SSLContext ssl_context_obtained,
                                     KeyManager[] manager, TrustManager[] wrapped_manager);

    void onException(Throwable e);
}

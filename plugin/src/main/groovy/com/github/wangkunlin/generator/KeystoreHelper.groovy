package com.github.wangkunlin.generator

import com.android.annotations.NonNull
import com.android.annotations.Nullable
import com.android.prefs.AndroidLocation
import com.android.utils.EnvironmentProvider
import com.android.utils.ILogger
import com.android.utils.Pair
import com.android.utils.StdLogger
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v1CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import javax.security.auth.x500.X500Principal
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
/**
 * On 2021-10-10
 */
class KeystoreHelper {

    static boolean createNewStore(
            @Nullable String storeType,
            @NonNull File storeFile,
            @NonNull String storePassword,
            @NonNull String keyPassword,
            @NonNull String keyAlias,
            @NonNull String dn,
            int validityYears) throws Exception {

        if (storeType == null) {
            storeType = KeyStore.getDefaultType()
        }

        KeyStore ks = KeyStore.getInstance(storeType)
        ks.load(null, null)

        Pair<PrivateKey, X509Certificate> generated = generateKeyAndCertificate("RSA",
                "SHA1withRSA", validityYears, dn)
        ks.setKeyEntry(keyAlias, generated.getFirst(), keyPassword.toCharArray(),
                [generated.getSecond()] as Certificate[])
        FileOutputStream fos = new FileOutputStream(storeFile)
        boolean threw = true
        try {
            ks.store(fos, storePassword.toCharArray())
            threw = false
        } finally {
            close(fos, threw)
        }

        return true
    }

    static void close(@Nullable Closeable closeable, boolean swallowIOException)
            throws IOException {
        if (closeable == null) {
            return
        }
        try {
            closeable.close()
        } catch (IOException e) {
            if (!swallowIOException) {
                throw e
            }
        }
    }

    private static Pair<PrivateKey, X509Certificate> generateKeyAndCertificate(
            @NonNull String asymmetric, @NonNull String sign, int validityYears,
            @NonNull String dn) throws Exception {

        KeyPair keyPair
        try {
            keyPair = KeyPairGenerator.getInstance(asymmetric).generateKeyPair()
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("Failed to generate key and certificate pair for "
                    + "algorithm '" + asymmetric + "'.", e)
        }

        Date notBefore = new Date(System.currentTimeMillis())
        Date notAfter = new Date(System.currentTimeMillis() + validityYears * 365L * 24 * 60 * 60
                * 1000)

        X500Name issuer = new X500Name(new X500Principal(dn).getName())

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(
                keyPair.getPublic().getEncoded())
        X509v1CertificateBuilder builder = new X509v1CertificateBuilder(issuer, BigInteger.ONE,
                notBefore, notAfter, issuer, publicKeyInfo)

        ContentSigner signer
        try {
            signer = new JcaContentSignerBuilder(sign).setProvider(
                    new BouncyCastleProvider()).build(keyPair.getPrivate())
        } catch (OperatorCreationException e) {
            throw new Exception("Failed to build content signer with signature algorithm '"
                    + sign + "'.", e)
        }

        X509CertificateHolder holder = builder.build(signer)

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())

        X509Certificate certificate
        try {
            certificate = converter.getCertificate(holder)
        } catch (CertificateException e) {
            throw new Exception("Failed to obtain the self-signed certificate.", e)
        }

        return Pair.of(keyPair.getPrivate(), certificate)
    }

    /**
     * Returns the location of the default debug keystore.
     *
     * @return The location of the default debug keystore
     * @throws com.android.prefs.AndroidLocation.AndroidLocationException if the location cannot be computed
     */
    @NonNull
    static String defaultDebugKeystoreLocation() throws Exception {
        return defaultDebugKeystoreLocation(
                EnvironmentProvider.DIRECT, new StdLogger(StdLogger.Level.VERBOSE))
    }

    /**
     * Returns the location of the default debug keystore.
     *
     * @return The location of the default debug keystore
     * @throws com.android.prefs.AndroidLocation.AndroidLocationException if the location cannot be computed
     */
    @NonNull
    static String defaultDebugKeystoreLocation(
            @NonNull EnvironmentProvider environmentProvider, @NonNull ILogger logger)
            throws Exception {
        // this is guaranteed to either return a non null value (terminated with a platform
        // specific separator), or throw.
        String folder = AndroidLocation.getFolder(environmentProvider, logger)
        return folder + "debug.keystore"
    }

}

package io.jenkins.plugins.akeyless.credentials.provider.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;

/**
 * Builds a PKCS#12 {@link java.security.KeyStore} from PEM certificate and private key returned by
 * {@code get-certificate-value}.
 */
public final class PemPkcs12Util {

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([^-]+)-----\\s*([\\s\\S]*?)-----END \\1-----", Pattern.MULTILINE);

    private PemPkcs12Util() {}

    @Nonnull
    public static java.security.KeyStore buildPkcs12KeyStore(
            @Nonnull String certificatePem,
            @Nonnull String privateKeyPem,
            char[] password) throws GeneralSecurityException, IOException {
        X509Certificate cert = parseCertificate(certificatePem);
        PrivateKey privateKey = parsePrivateKey(privateKeyPem);
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        ks.setKeyEntry("akeyless", privateKey, password, new Certificate[]{cert});
        return ks;
    }

    private static X509Certificate parseCertificate(String pem) throws CertificateException {
        byte[] der = decodeFirstPemBlock(pem, "CERTIFICATE");
        if (der == null) {
            throw new CertificateException("No PEM CERTIFICATE block found");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private static PrivateKey parsePrivateKey(String pem) throws GeneralSecurityException {
        byte[] der = decodeFirstPemBlock(pem, "PRIVATE KEY");
        if (der == null) {
            der = decodeFirstPemBlock(pem, "EC PRIVATE KEY");
        }
        if (der == null) {
            throw new InvalidKeySpecException("No PEM private key block found");
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    private static byte[] decodeFirstPemBlock(String pem, String kind) {
        Matcher m = PEM_BLOCK.matcher(pem);
        while (m.find()) {
            if (kind.equals(m.group(1).trim())) {
                String b64 = m.group(2).replaceAll("\\s", "");
                return Base64.getDecoder().decode(b64);
            }
        }
        return null;
    }
}

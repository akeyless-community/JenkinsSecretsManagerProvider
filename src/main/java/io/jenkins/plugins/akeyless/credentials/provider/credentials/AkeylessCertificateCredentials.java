package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.AkeylessCredentialsProvider;
import io.jenkins.plugins.akeyless.credentials.provider.client.PemPkcs12Util;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.GetSecretValueResult;
import hudson.Extension;
import hudson.util.Secret;

import edu.umd.cs.findbugs.annotations.NonNull;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;

public class AkeylessCertificateCredentials extends BaseStandardCredentials implements StandardCertificateCredentials {

    private final String akeylessPath;

    public AkeylessCertificateCredentials(String id, String akeylessPath, String description) {
        super(id, description);
        this.akeylessPath = akeylessPath != null ? akeylessPath : id;
    }

    @NonNull
    @Override
    public KeyStore getKeyStore() {
        AkeylessClient client = AkeylessStringCredentials.getClient();
        try {
            GetSecretValueResult r = client.getSecretValue(akeylessPath);
            char[] ksPassword = getPassword().getPlainText().toCharArray();
            if (r.isPemCertificatePair()) {
                return PemPkcs12Util.buildPkcs12KeyStore(r.getCertificatePem(), r.getPrivateKeyPem(), ksPassword);
            }
            byte[] bytes = r.getBinaryValue() != null ? r.getBinaryValue()
                    : r.getStringValue().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(bytes), ksPassword);
            return ks;
        } catch (ApiException e) {
            throw new CredentialsUnavailableException("Could not retrieve secret from Akeyless: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CredentialsUnavailableException("Could not load keystore: " + e.getMessage(), e);
        }
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return Secret.fromString("");
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Certificate"; }

        @Override
        public boolean isApplicable(CredentialsProvider scope) {
            return scope instanceof AkeylessCredentialsProvider;
        }
    }
}

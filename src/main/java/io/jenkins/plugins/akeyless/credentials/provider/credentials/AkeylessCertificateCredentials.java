package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.GetSecretValueResult;
import hudson.util.Secret;

import edu.umd.cs.findbugs.annotations.NonNull;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;

public class AkeylessCertificateCredentials extends BaseStandardCredentials implements StandardCertificateCredentials {

    private static final DescriptorImpl DESCRIPTOR_INSTANCE = new DescriptorImpl();

    private final String akeylessPath;

    public AkeylessCertificateCredentials(String id, String akeylessPath, String description) {
        super(id, description);
        this.akeylessPath = akeylessPath != null ? akeylessPath : id;
    }

    @Override
    public CredentialsDescriptor getDescriptor() {
        return DESCRIPTOR_INSTANCE;
    }

    @NonNull
    @Override
    public KeyStore getKeyStore() {
        AkeylessClient client = AkeylessStringCredentials.getClient();
        try {
            GetSecretValueResult r = client.getSecretValue(akeylessPath);
            byte[] bytes = r.getBinaryValue() != null ? r.getBinaryValue()
                    : r.getStringValue().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(bytes), getPassword().getPlainText().toCharArray());
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

    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Certificate"; }
    }
}

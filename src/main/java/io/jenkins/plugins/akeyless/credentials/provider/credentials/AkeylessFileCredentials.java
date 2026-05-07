package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.SecretBytes;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.AkeylessCredentialsProvider;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.GetSecretValueResult;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;

public class AkeylessFileCredentials extends BaseStandardCredentials implements StandardCredentials {

    private final String akeylessPath;
    private final String filename;

    public AkeylessFileCredentials(String id, String akeylessPath, String description, String filename) {
        super(id, description);
        this.akeylessPath = akeylessPath != null ? akeylessPath : id;
        this.filename = filename != null ? filename : id;
    }

    @NonNull
    public String getFileName() {
        return filename;
    }

    @NonNull
    public SecretBytes getContent() {
        AkeylessClient client = AkeylessStringCredentials.getClient();
        try {
            GetSecretValueResult r = client.getSecretValue(akeylessPath);
            if (r.isString()) {
                return SecretBytes.fromBytes(r.getStringValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            if (r.getBinaryValue() != null) {
                return SecretBytes.fromBytes(r.getBinaryValue());
            }
            throw new CredentialsUnavailableException("Secret '" + akeylessPath + "' has no value");
        } catch (ApiException e) {
            throw new CredentialsUnavailableException("Could not retrieve secret from Akeyless: " + e.getMessage(), e);
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Secret File"; }

        @Override
        public boolean isApplicable(CredentialsProvider scope) {
            return scope instanceof AkeylessCredentialsProvider;
        }
    }
}

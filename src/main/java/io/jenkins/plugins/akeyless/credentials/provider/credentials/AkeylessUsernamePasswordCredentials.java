package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.util.Secret;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.GetSecretValueResult;

import edu.umd.cs.findbugs.annotations.NonNull;

public class AkeylessUsernamePasswordCredentials extends BaseStandardCredentials implements StandardUsernamePasswordCredentials {

    private static final DescriptorImpl DESCRIPTOR_INSTANCE = new DescriptorImpl();

    private final String akeylessPath;
    private final String username;

    public AkeylessUsernamePasswordCredentials(String id, String akeylessPath, String description, String username) {
        super(id, description);
        this.akeylessPath = akeylessPath != null ? akeylessPath : id;
        this.username = username != null ? username : "";
    }

    @Override
    public CredentialsDescriptor getDescriptor() {
        return DESCRIPTOR_INSTANCE;
    }

    @NonNull
    @Override
    public String getUsername() {
        return username;
    }

    @NonNull
    @Override
    public Secret getPassword() {
        AkeylessClient client = AkeylessStringCredentials.getClient();
        try {
            GetSecretValueResult r = client.getSecretValue(akeylessPath);
            if (r.isString()) {
                return Secret.fromString(r.getStringValue());
            }
            throw new CredentialsUnavailableException("Secret '" + akeylessPath + "' is binary, cannot use as password");
        } catch (ApiException e) {
            throw new CredentialsUnavailableException("Could not retrieve secret from Akeyless: " + e.getMessage(), e);
        }
    }

    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Username/Password"; }
    }
}

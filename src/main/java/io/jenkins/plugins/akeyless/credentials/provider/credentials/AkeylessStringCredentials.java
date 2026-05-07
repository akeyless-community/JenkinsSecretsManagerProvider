package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.util.Secret;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.GetSecretValueResult;
import io.jenkins.plugins.akeyless.credentials.provider.config.AkeylessCredentialsProviderConfig;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import io.jenkins.plugins.akeyless.credentials.provider.AkeylessCredentialsProvider;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;

import java.util.logging.Level;
import java.util.logging.Logger;

public class AkeylessStringCredentials extends BaseStandardCredentials implements StringCredentials {

    private static final Logger LOG = Logger.getLogger(AkeylessStringCredentials.class.getName());

    private final String akeylessPath;

    public AkeylessStringCredentials(String id, String akeylessPath, String description) {
        super(id, description);
        this.akeylessPath = akeylessPath != null ? akeylessPath : id;
    }

    @NonNull
    public Secret getSecret() {
        AkeylessClient client = getClient();
        try {
            LOG.log(Level.INFO, "Akeyless Credentials Provider: fetching secret value for credential id={0} path={1}", new Object[]{getId(), akeylessPath});
            GetSecretValueResult r = client.getSecretValue(akeylessPath);
            if (r.isString()) {
                return Secret.fromString(r.getStringValue());
            }
            throw new CredentialsUnavailableException("Secret '" + akeylessPath + "' is binary, cannot use as string");
        } catch (ApiException e) {
            LOG.log(Level.WARNING, "Akeyless Credentials Provider: failed to get secret for path={0}: {1}", new Object[]{akeylessPath, e.getMessage()});
            throw new CredentialsUnavailableException("Could not retrieve secret from Akeyless: " + e.getMessage(), e);
        }
    }

    static AkeylessClient getClient() {
        AkeylessCredentialsProviderConfig config = AkeylessCredentialsProviderConfig.get();
        if (config == null || !config.isConfigured()) {
            throw new CredentialsUnavailableException("Akeyless Credentials Provider is not configured");
        }
        AkeylessClient client = config.buildClient();
        if (client == null) {
            throw new CredentialsUnavailableException("Could not connect to Akeyless (check URL and credential)");
        }
        return client;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Secret Text"; }

        @Override
        public boolean isApplicable(CredentialsProvider scope) {
            return scope instanceof AkeylessCredentialsProvider;
        }
    }
}

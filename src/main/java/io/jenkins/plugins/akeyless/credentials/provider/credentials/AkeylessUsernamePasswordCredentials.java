package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.util.Secret;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.AkeylessCredentialsProvider;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.GetSecretValueResult;

import edu.umd.cs.findbugs.annotations.NonNull;

public class AkeylessUsernamePasswordCredentials extends BaseStandardCredentials implements StandardUsernamePasswordCredentials {

    private final String akeylessPath;
    private final String usernameFromTag;
    private final String valueFormat;

    private transient volatile Parsed parsed;

    public AkeylessUsernamePasswordCredentials(String id, String akeylessPath, String description, String usernameFromTag, String valueFormat) {
        super(id, description);
        this.akeylessPath = akeylessPath != null ? akeylessPath : id;
        this.usernameFromTag = usernameFromTag != null ? usernameFromTag : "";
        this.valueFormat = valueFormat != null ? valueFormat : "";
    }

    @NonNull
    @Override
    public String getUsername() {
        return load().username;
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return load().password;
    }

    private Parsed load() {
        Parsed p = parsed;
        if (p != null) {
            return p;
        }
        synchronized (this) {
            if (parsed != null) {
                return parsed;
            }
            AkeylessClient client = AkeylessStringCredentials.getClient();
            try {
                GetSecretValueResult r = client.getSecretValue(akeylessPath);
                if (!r.isString()) {
                    throw new CredentialsUnavailableException("Secret '" + akeylessPath + "' is binary, cannot use as password");
                }
                String raw = r.getStringValue();
                boolean useJson = SecretJsonBodies.isJsonFormat(valueFormat)
                        || (valueFormat.isEmpty() && SecretJsonBodies.looksLikeJsonObject(raw));
                if (useJson) {
                    SecretJsonBodies.UsernamePasswordJson j = SecretJsonBodies.parseUsernamePassword(raw);
                    if (j == null) {
                        throw new CredentialsUnavailableException("Secret '" + akeylessPath + "' JSON must include password (and optionally username) fields");
                    }
                    String user = !j.username.isEmpty() ? j.username : usernameFromTag;
                    parsed = new Parsed(user, Secret.fromString(j.password));
                } else {
                    parsed = new Parsed(usernameFromTag, Secret.fromString(raw));
                }
                return parsed;
            } catch (ApiException e) {
                throw new CredentialsUnavailableException("Could not retrieve secret from Akeyless: " + e.getMessage(), e);
            }
        }
    }

    private static final class Parsed {
        final String username;
        final Secret password;

        Parsed(String username, Secret password) {
            this.username = username != null ? username : "";
            this.password = password;
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless Username/Password"; }

        @Override
        public boolean isApplicable(CredentialsProvider scope) {
            return scope instanceof AkeylessCredentialsProvider;
        }
    }
}

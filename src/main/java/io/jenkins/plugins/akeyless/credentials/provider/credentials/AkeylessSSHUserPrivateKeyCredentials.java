package io.jenkins.plugins.akeyless.credentials.provider.credentials;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import hudson.Extension;
import hudson.util.Secret;
import io.akeyless.client.ApiException;
import io.jenkins.plugins.akeyless.credentials.provider.AkeylessCredentialsProvider;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient;
import io.jenkins.plugins.akeyless.credentials.provider.client.AkeylessClient.GetSecretValueResult;

import edu.umd.cs.findbugs.annotations.NonNull;

import java.util.Collections;
import java.util.List;

public class AkeylessSSHUserPrivateKeyCredentials extends BaseStandardCredentials implements SSHUserPrivateKey {

    private static final Secret NO_PASSPHRASE = Secret.fromString("");

    private final String akeylessPath;
    private final String usernameFromTag;
    private final String valueFormat;

    private transient volatile SshParsed parsed;

    public AkeylessSSHUserPrivateKeyCredentials(String id, String akeylessPath, String description, String usernameFromTag, String valueFormat) {
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

    @Override
    @Deprecated
    public String getPrivateKey() {
        return getPrivateKeys().isEmpty() ? "" : getPrivateKeys().get(0);
    }

    @Override
    public Secret getPassphrase() {
        return load().passphrase;
    }

    @NonNull
    @Override
    public List<String> getPrivateKeys() {
        return Collections.singletonList(load().privateKey);
    }

    private SshParsed load() {
        SshParsed p = parsed;
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
                    throw new CredentialsUnavailableException("Secret '" + akeylessPath + "' is binary, cannot use as SSH key");
                }
                String raw = r.getStringValue();
                boolean useJson = SecretJsonBodies.isJsonFormat(valueFormat)
                        || (valueFormat.isEmpty() && SecretJsonBodies.looksLikeJsonObject(raw));
                if (useJson) {
                    SecretJsonBodies.SshJson j = SecretJsonBodies.parseSsh(raw);
                    if (j == null) {
                        throw new CredentialsUnavailableException("Secret '" + akeylessPath + "' JSON must include privateKey (and optionally username, passphrase) fields");
                    }
                    String user = !j.username.isEmpty() ? j.username : usernameFromTag;
                    Secret pass = j.passphrase.isEmpty() ? NO_PASSPHRASE : Secret.fromString(j.passphrase);
                    parsed = new SshParsed(user, j.privateKey, pass);
                } else {
                    parsed = new SshParsed(usernameFromTag, raw, NO_PASSPHRASE);
                }
                return parsed;
            } catch (ApiException e) {
                throw new CredentialsUnavailableException("Could not retrieve secret from Akeyless: " + e.getMessage(), e);
            }
        }
    }

    private static final class SshParsed {
        final String username;
        final String privateKey;
        final Secret passphrase;

        SshParsed(String username, String privateKey, Secret passphrase) {
            this.username = username != null ? username : "";
            this.privateKey = privateKey != null ? privateKey : "";
            this.passphrase = passphrase != null ? passphrase : NO_PASSPHRASE;
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() { return "Akeyless SSH Private Key"; }

        @Override
        public boolean isApplicable(CredentialsProvider scope) {
            return scope instanceof AkeylessCredentialsProvider;
        }
    }
}

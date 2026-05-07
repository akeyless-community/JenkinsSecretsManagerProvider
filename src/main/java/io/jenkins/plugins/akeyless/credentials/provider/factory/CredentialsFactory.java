package io.jenkins.plugins.akeyless.credentials.provider.factory;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import io.jenkins.plugins.akeyless.credentials.provider.credentials.AkeylessCertificateCredentials;
import io.jenkins.plugins.akeyless.credentials.provider.credentials.AkeylessFileCredentials;
import io.jenkins.plugins.akeyless.credentials.provider.credentials.AkeylessSSHUserPrivateKeyCredentials;
import io.jenkins.plugins.akeyless.credentials.provider.credentials.AkeylessStringCredentials;
import io.jenkins.plugins.akeyless.credentials.provider.credentials.AkeylessUsernamePasswordCredentials;

import java.util.Map;
import java.util.Optional;

/**
 * Creates Jenkins credential instances from Akeyless item metadata (name, description, tags) and client for on-demand fetch.
 */
public final class CredentialsFactory {

    private CredentialsFactory() {}

    /**
     * Create a Jenkins credential from an Akeyless item. Credentials do not store the API client
     * so they remain serializable and safe for Jenkins class filter; the client is built on demand
     * when the secret value is fetched.
     * @param id Jenkins credential id (sanitized path, [a-zA-Z0-9_.-]+)
     * @param akeylessPath full Akeyless path for getSecretValue API
     * @param description optional description
     * @param tags tags from Akeyless (e.g. jenkins:credentials:type, jenkins:credentials:username)
     * @return credential if type is supported, empty otherwise
     */
    public static Optional<StandardCredentials> create(
            String id,
            String akeylessPath,
            String description,
            Map<String, String> tags) {
        String type = tags.getOrDefault(Tags.TYPE, Type.STRING);
        String username = tags.getOrDefault(Tags.USERNAME, "");
        String filename = tags.getOrDefault(Tags.FILENAME, id);
        String valueFormat = tags.getOrDefault(Tags.VALUE_FORMAT, "").trim();

        switch (type) {
            case Type.STRING:
                return Optional.of(new AkeylessStringCredentials(id, akeylessPath, description));
            case Type.USERNAME_PASSWORD:
                return Optional.of(new AkeylessUsernamePasswordCredentials(id, akeylessPath, description, username, valueFormat));
            case Type.SSH_USER_PRIVATE_KEY:
                return Optional.of(new AkeylessSSHUserPrivateKeyCredentials(id, akeylessPath, description, username, valueFormat));
            case Type.CERTIFICATE:
                return Optional.of(new AkeylessCertificateCredentials(id, akeylessPath, description));
            case Type.FILE:
                return Optional.of(new AkeylessFileCredentials(id, akeylessPath, description, filename));
            default:
                return Optional.empty();
        }
    }
}

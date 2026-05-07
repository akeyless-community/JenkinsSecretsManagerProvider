package io.jenkins.plugins.akeyless.credentials.provider.factory;

/**
 * Tag keys on Akeyless items used to map to Jenkins credential types (same convention as AWS Secrets Manager Credentials Provider).
 *
 * @see <a href="https://plugins.jenkins.io/aws-secrets-manager-credentials-provider/">AWS Secrets Manager Credentials Provider</a>
 */
public abstract class Tags {
    private static final String NAMESPACE = "jenkins:credentials:";

    public static final String FILENAME = NAMESPACE + "filename";
    public static final String TYPE = NAMESPACE + "type";
    public static final String USERNAME = NAMESPACE + "username";
    /**
     * Optional. For {@code usernamePassword} / {@code sshUserPrivateKey} when the secret value is JSON:
     * set to {@code json} to parse username/password (or username/privateKey) from the secret body.
     * When unset, username comes from {@link #USERNAME} tag and the whole secret body is the password (or private key).
     */
    public static final String VALUE_FORMAT = NAMESPACE + "valueFormat";

    private Tags() {}
}

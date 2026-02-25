package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.Secret;
import io.akeyless.client.model.Auth;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nullable;

/**
 * Certificate-based authentication with Akeyless.
 * Requires the certificate data (PEM) and private key data (PEM), both stored encrypted.
 */
public class CertificateAuthMethod extends AuthMethod {

    private Secret certData;
    private Secret keyData;

    @DataBoundConstructor
    public CertificateAuthMethod() {}

    public Secret getCertData() { return certData; }

    @DataBoundSetter
    public void setCertData(Secret certData) { this.certData = certData; }

    public Secret getKeyData() { return keyData; }

    @DataBoundSetter
    public void setKeyData(Secret keyData) { this.keyData = keyData; }

    @Override
    public Auth buildAuth(@Nullable String accessId) {
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setCertData(Secret.toString(certData));
        auth.setKeyData(Secret.toString(keyData));
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        return accessId != null && !accessId.isBlank()
                && certData != null && !Secret.toString(certData).isBlank()
                && keyData != null && !Secret.toString(keyData).isBlank();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "Certificate"; }
    }
}

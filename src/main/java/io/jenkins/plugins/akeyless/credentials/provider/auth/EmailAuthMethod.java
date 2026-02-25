package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.Secret;
import io.akeyless.client.model.Auth;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nullable;

/**
 * Email/password authentication with Akeyless.
 * Does not require an Access ID — uses admin email and password directly.
 */
public class EmailAuthMethod extends AuthMethod {

    private String adminEmail;
    private Secret adminPassword;

    @DataBoundConstructor
    public EmailAuthMethod() {}

    public String getAdminEmail() { return adminEmail; }

    @DataBoundSetter
    public void setAdminEmail(String adminEmail) { this.adminEmail = adminEmail; }

    public Secret getAdminPassword() { return adminPassword; }

    @DataBoundSetter
    public void setAdminPassword(Secret adminPassword) { this.adminPassword = adminPassword; }

    @Override
    public Auth buildAuth(@Nullable String accessId) {
        Auth auth = new Auth();
        auth.setAdminEmail(adminEmail);
        auth.setAdminPassword(Secret.toString(adminPassword));
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        return adminEmail != null && !adminEmail.isBlank()
                && adminPassword != null && !Secret.toString(adminPassword).isBlank();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "Email"; }
    }
}

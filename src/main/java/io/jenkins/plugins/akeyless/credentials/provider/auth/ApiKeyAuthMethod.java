package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.Secret;
import io.akeyless.client.model.Auth;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nullable;

public class ApiKeyAuthMethod extends AuthMethod {

    private Secret accessKey;

    @DataBoundConstructor
    public ApiKeyAuthMethod() {}

    public Secret getAccessKey() { return accessKey; }

    @DataBoundSetter
    public void setAccessKey(Secret accessKey) { this.accessKey = accessKey; }

    @Override
    public Auth buildAuth(@Nullable String accessId) {
        Auth auth = new Auth();
        auth.setAccessId(accessId);
        auth.setAccessKey(Secret.toString(accessKey));
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        return accessId != null && !accessId.isBlank()
                && accessKey != null && !Secret.toString(accessKey).isBlank();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "API Key"; }
    }
}

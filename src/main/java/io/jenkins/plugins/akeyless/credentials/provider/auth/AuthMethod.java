package io.jenkins.plugins.akeyless.credentials.provider.auth;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import io.akeyless.client.model.Auth;
import jenkins.model.Jenkins;

import javax.annotation.Nullable;

public abstract class AuthMethod extends AbstractDescribableImpl<AuthMethod> {

    public abstract Auth buildAuth(@Nullable String accessId) throws Exception;

    public abstract boolean isConfigured(@Nullable String accessId);

    public static DescriptorExtensionList<AuthMethod, Descriptor<AuthMethod>> all() {
        return Jenkins.get().getDescriptorList(AuthMethod.class);
    }
}

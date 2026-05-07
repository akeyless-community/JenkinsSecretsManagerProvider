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
        auth.setAccessId(trimCopyPasted(accessId));
        auth.setAccessKey(normalizeAccessKey(Secret.toString(accessKey)));
        return auth;
    }

    @Override
    public boolean isConfigured(@Nullable String accessId) {
        String id = trimCopyPasted(accessId);
        if (id == null || id.isBlank() || accessKey == null) {
            return false;
        }
        return !normalizeAccessKey(Secret.toString(accessKey)).isBlank();
    }

    /** Trims the access id; Akeyless rejects auth when the id contains accidental spaces. */
    private static String trimCopyPasted(@Nullable String s) {
        return s == null ? null : s.trim();
    }

    /**
     * Akeyless decodes the access key as Base64 on the gateway. Remove all whitespace so line-wrapped or
     * copy-pasted keys still decode; trim ends so stray newlines do not break decoding.
     */
    private static String normalizeAccessKey(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.trim().replaceAll("\\s+", "");
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthMethod> {
        @Override
        public String getDisplayName() { return "API Key"; }
    }
}
